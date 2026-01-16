package ffmpeg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BlackDetectResult contains the result of black frame detection.
type BlackDetectResult struct {
	HasBlackFrames    bool
	BlackDuration     float64
	BlackStartTime    float64
	TotalDuration     float64
	BlackRatio        float64
	FullyBlack        bool
}

// SilenceDetectResult contains the result of silence detection.
type SilenceDetectResult struct {
	HasSilence       bool
	SilenceDuration  float64
	SilenceStartTime float64
	TotalDuration    float64
	SilenceRatio     float64
	FullySilent      bool
}

// AnalysisResult contains the combined analysis result.
type AnalysisResult struct {
	Black   *BlackDetectResult
	Silence *SilenceDetectResult
}

// Analyzer handles FFmpeg-based media analysis.
type Analyzer struct {
	ffmpegPath  string
	ffprobePath string
	tmpDir      string
	silenceDBThreshold float64
}

// NewAnalyzer creates a new FFmpeg analyzer.
func NewAnalyzer(ffmpegPath, ffprobePath, tmpDir string, silenceDBThreshold float64) *Analyzer {
	if ffmpegPath == "" {
		ffmpegPath = "ffmpeg"
	}
	if ffprobePath == "" {
		ffprobePath = "ffprobe"
	}
	if silenceDBThreshold == 0 {
		silenceDBThreshold = -50
	}
	return &Analyzer{
		ffmpegPath:  ffmpegPath,
		ffprobePath: ffprobePath,
		tmpDir:      tmpDir,
		silenceDBThreshold: silenceDBThreshold,
	}
}

// EnsureTmpDir creates the temporary directory if it doesn't exist.
func (a *Analyzer) EnsureTmpDir() error {
	return os.MkdirAll(a.tmpDir, 0755)
}

// AnalyzeSegment performs black and silence detection on a segment file.
func (a *Analyzer) AnalyzeSegment(ctx context.Context, segmentPath string) (*AnalysisResult, error) {
	// First, get the duration of the segment
	duration, err := a.getDuration(ctx, segmentPath)
	if err != nil {
		return nil, fmt.Errorf("get duration: %w", err)
	}

	// Analyze for black frames
	blackResult, err := a.detectBlack(ctx, segmentPath, duration)
	if err != nil {
		return nil, fmt.Errorf("detect black: %w", err)
	}

	// Analyze for silence
	silenceResult, err := a.detectSilence(ctx, segmentPath, duration)
	if err != nil {
		return nil, fmt.Errorf("detect silence: %w", err)
	}

	return &AnalysisResult{
		Black:   blackResult,
		Silence: silenceResult,
	}, nil
}

// getDuration gets the duration of a media file using ffprobe.
func (a *Analyzer) getDuration(ctx context.Context, filePath string) (float64, error) {
	args := []string{
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "default=noprint_wrappers=1:nokey=1",
		filePath,
	}

	cmd := exec.CommandContext(ctx, a.ffprobePath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("ffprobe failed: %w (stderr: %s)", err, stderr.String())
	}

	durationStr := strings.TrimSpace(stdout.String())
	duration, err := strconv.ParseFloat(durationStr, 64)
	if err != nil {
		return 0, fmt.Errorf("parse duration: %w", err)
	}

	return duration, nil
}

// detectBlack detects black frames in a media file.
func (a *Analyzer) detectBlack(ctx context.Context, filePath string, totalDuration float64) (*BlackDetectResult, error) {
	// blackdetect parameters:
	// d=0.1: minimum black duration to detect (100ms)
	// pix_th=0.10: pixel threshold (0.0-1.0)
	args := []string{
		"-i", filePath,
		"-vf", "blackdetect=d=0.1:pix_th=0.10",
		"-an",
		"-f", "null",
		"-",
	}

	cmd := exec.CommandContext(ctx, a.ffmpegPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// FFmpeg outputs blackdetect info to stderr
	_ = cmd.Run() // Ignore error as ffmpeg returns non-zero for some valid cases

	result := &BlackDetectResult{
		TotalDuration: totalDuration,
	}

	// Parse blackdetect output
	// Format: [blackdetect @ 0x...] black_start:0 black_end:2.0 black_duration:2.0
	blackRegex := regexp.MustCompile(`black_start:([0-9.]+)\s+black_end:([0-9.]+)\s+black_duration:([0-9.]+)`)
	matches := blackRegex.FindAllStringSubmatch(stderr.String(), -1)

	var totalBlackDuration float64
	var firstBlackStart float64 = -1

	for _, match := range matches {
		if len(match) >= 4 {
			result.HasBlackFrames = true
			blackStart, _ := strconv.ParseFloat(match[1], 64)
			blackDuration, _ := strconv.ParseFloat(match[3], 64)

			totalBlackDuration += blackDuration
			if firstBlackStart < 0 {
				firstBlackStart = blackStart
			}
		}
	}

	result.BlackDuration = totalBlackDuration
	if firstBlackStart >= 0 {
		result.BlackStartTime = firstBlackStart
	}

	if totalDuration > 0 {
		result.BlackRatio = totalBlackDuration / totalDuration
		// Consider fully black if >90% is black
		result.FullyBlack = result.BlackRatio > 0.9
	}

	return result, nil
}

// detectSilence detects silence in a media file.
func (a *Analyzer) detectSilence(ctx context.Context, filePath string, totalDuration float64) (*SilenceDetectResult, error) {
	// silencedetect parameters:
	// n=-50dB: noise threshold
	// d=0.5: minimum silence duration
	args := []string{
		"-i", filePath,
		"-af", fmt.Sprintf("silencedetect=n=%gdB:d=0.5", a.silenceDBThreshold),
		"-vn",
		"-f", "null",
		"-",
	}

	cmd := exec.CommandContext(ctx, a.ffmpegPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// FFmpeg outputs silencedetect info to stderr
	_ = cmd.Run() // Ignore error as ffmpeg returns non-zero for some valid cases

	result := &SilenceDetectResult{
		TotalDuration: totalDuration,
	}

	// Parse silencedetect output
	// Format: [silencedetect @ 0x...] silence_start: 0
	// Format: [silencedetect @ 0x...] silence_end: 2.0 | silence_duration: 2.0
	startRegex := regexp.MustCompile(`silence_start:\s*([0-9.]+)`)
	endRegex := regexp.MustCompile(`silence_end:\s*([0-9.]+)\s*\|\s*silence_duration:\s*([0-9.]+)`)

	stderrStr := stderr.String()
	startMatches := startRegex.FindAllStringSubmatch(stderrStr, -1)
	endMatches := endRegex.FindAllStringSubmatch(stderrStr, -1)

	var totalSilenceDuration float64
	var firstSilenceStart float64 = -1

	// Track silence starts
	for _, match := range startMatches {
		if len(match) >= 2 {
			result.HasSilence = true
			silenceStart, _ := strconv.ParseFloat(match[1], 64)
			if firstSilenceStart < 0 {
				firstSilenceStart = silenceStart
			}
		}
	}

	// Calculate total silence duration
	for _, match := range endMatches {
		if len(match) >= 3 {
			silenceDuration, _ := strconv.ParseFloat(match[2], 64)
			totalSilenceDuration += silenceDuration
		}
	}

	// Handle case where silence continues to end of file (no silence_end)
	if len(startMatches) > len(endMatches) && len(startMatches) > 0 {
		lastStartMatch := startMatches[len(startMatches)-1]
		if len(lastStartMatch) >= 2 {
			lastStart, _ := strconv.ParseFloat(lastStartMatch[1], 64)
			remainingSilence := totalDuration - lastStart
			if remainingSilence > 0 {
				totalSilenceDuration += remainingSilence
			}
		}
	}

	result.SilenceDuration = totalSilenceDuration
	if firstSilenceStart >= 0 {
		result.SilenceStartTime = firstSilenceStart
	}

	if totalDuration > 0 {
		result.SilenceRatio = totalSilenceDuration / totalDuration
		// Consider fully silent if >90% is silent
		result.FullySilent = result.SilenceRatio > 0.9
	}

	return result, nil
}

// SaveSegment saves segment data to a temporary file and returns the path.
func (a *Analyzer) SaveSegment(monitorID string, data []byte) (string, error) {
	segmentDir := filepath.Join(a.tmpDir, monitorID)
	if err := os.MkdirAll(segmentDir, 0755); err != nil {
		return "", fmt.Errorf("create segment dir: %w", err)
	}

	filename := fmt.Sprintf("segment_%d.ts", time.Now().UnixNano())
	segmentPath := filepath.Join(segmentDir, filename)

	if err := os.WriteFile(segmentPath, data, 0644); err != nil {
		return "", fmt.Errorf("write segment: %w", err)
	}

	return segmentPath, nil
}

// CleanupSegment removes a segment file.
func (a *Analyzer) CleanupSegment(segmentPath string) error {
	return os.Remove(segmentPath)
}

// CleanupMonitor removes all segment files for a monitor.
func (a *Analyzer) CleanupMonitor(monitorID string) error {
	segmentDir := filepath.Join(a.tmpDir, monitorID)
	return os.RemoveAll(segmentDir)
}
