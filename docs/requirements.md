# YouTube配信監視システム 要件定義書

## 1. システム概要

### 1.1 目的

YouTubeライブ配信のリアルタイム監視を行い、以下の異常を自動検出・通知するシステムを構築する。

- 配信開始忘れ（スケジュール済み配信が開始されない）
- 映像のブラックアウト（黒画面の継続）
- 音声の欠落（無音状態の継続）

### 1.2 システム形態

- **アーキテクチャ**: Kubernetes上で動作するマイクロサービス
- **実行形態**: 常駐サービス（API Gateway + 監視Worker）
- **言語**: Go

---

## 2. システムアーキテクチャ

### 2.1 コンポーネント構成

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐       ┌─────────────────────────────────┐ │
│  │   API Gateway    │       │      監視Worker Pod Pool         │ │
│  │   (Deployment)   │       │  ┌───────┐ ┌───────┐ ┌───────┐  │ │
│  │                  │──────▶│  │Worker1│ │Worker2│ │Worker3│  │ │
│  │  - REST API      │       │  │(配信A)│ │(配信B)│ │(配信C)│  │ │
│  │  - Job管理       │       │  └───────┘ └───────┘ └───────┘  │ │
│  └──────────────────┘       └─────────────────────────────────┘ │
│           │                              │                       │
│           ▼                              ▼                       │
│  ┌──────────────────┐       ┌──────────────────┐                │
│  │  PostgreSQL      │       │   外部Webhook    │                │
│  │  (状態管理)       │       │   (コールバック)  │                │
│  └──────────────────┘       └──────────────────┘                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 コンポーネント詳細

#### 2.2.1 API Gateway

- 監視リクエストの受付・管理
- 監視Worker Podの作成・削除
- 監視状態の照会

#### 2.2.2 監視Worker

- 配信ごとに1つのPodとして起動
- セグメント取得・解析を実行
- 異常検出時にWebhookコールバック

---

## 3. API仕様

### 3.1 監視開始 API

#### エンドポイント

```
POST /api/v1/monitors
```

#### リクエストボディ

```json
{
  "stream_url": "https://www.youtube.com/watch?v=XXXXXXXXXXX",
  "callback_url": "https://example.com/webhook/stream-alert",
  "config": {
    "check_interval_sec": 10,
    "blackout_threshold_sec": 30,
    "silence_threshold_sec": 30,
    "silence_db_threshold": -50,
    "scheduled_start_time": "2024-01-15T20:00:00+09:00",
    "start_delay_tolerance_sec": 300
  },
  "metadata": {
    "channel_name": "Example Channel",
    "stream_title": "配信タイトル",
    "custom_data": {}
  }
}
```

#### リクエストパラメータ詳細

| パラメータ                         | 型     | 必須 | デフォルト | 説明                                                   |
| ---------------------------------- | ------ | ---- | ---------- | ------------------------------------------------------ |
| `stream_url`                       | string | ○    | -          | YouTube配信URL（watch URLのみ、チャンネルURLは非対応） |
| `callback_url`                     | string | ○    | -          | 異常検出時のWebhookコールバックURL                     |
| `config.check_interval_sec`        | int    | -    | 10         | セグメント解析間隔（秒）                               |
| `config.blackout_threshold_sec`    | int    | -    | 30         | ブラックアウト判定閾値（秒）                           |
| `config.silence_threshold_sec`     | int    | -    | 30         | 無音判定閾値（秒）                                     |
| `config.silence_db_threshold`      | float  | -    | -50        | 無音判定の音量閾値（dB）                               |
| `config.scheduled_start_time`      | string | -    | null       | 予定開始時刻（ISO 8601形式）                           |
| `config.start_delay_tolerance_sec` | int    | -    | 300        | 開始遅延許容時間（秒）                                 |
| `metadata`                         | object | -    | {}         | コールバック時に含める任意のメタデータ                 |

#### 重複チェック

同一の `stream_url` で既にアクティブな監視が存在する場合、HTTP 409 (Conflict) を返却する。

#### レスポンス

```json
{
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "status": "initializing",
  "created_at": "2024-01-15T19:55:00+09:00"
}
```

#### monitor_id形式

| 項目 | 値 | 説明 |
| ---- | -- | ---- |
| 形式 | `mon-` + UUIDv7（ハイフン付き、標準UUID形式） | DNS-1123準拠（ハイフンのみ許可） |
| 例 | `mon-0190a5c8-e4b0-7d8a-9c1d-2e3f4a5b6c7d` | Pod、環境変数、APIレスポンス全で統一 |

※ `mon-`プレフィックスはDNS-1123制約に準拠し、内部・外部で統一。UUIDv7のためタイムスタンプ順でソート可能。標準UUIDライブラリがハイフン付きで出力するため、その形式を使用する。

### 3.2 監視停止 API

#### エンドポイント

```
DELETE /api/v1/monitors/{monitor_id}
```

#### レスポンス

```json
{
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "status": "stopped",
  "stopped_at": "2024-01-15T21:30:00+09:00"
}
```

### 3.3 監視状態取得 API

#### エンドポイント

```
GET /api/v1/monitors/{monitor_id}
```

#### レスポンス

```json
{
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "stream_url": "https://www.youtube.com/watch?v=XXXXXXXXXXX",
  "status": "monitoring",
  "stream_status": "live",
  "health": {
    "video": "ok",
    "audio": "ok",
    "last_check_at": "2024-01-15T20:15:30+09:00"
  },
  "statistics": {
    "total_segments_analyzed": 150,
    "blackout_events": 0,
    "silence_events": 1
  },
  "created_at": "2024-01-15T19:55:00+09:00"
}
```

### 3.4 監視一覧取得 API

#### エンドポイント

```
GET /api/v1/monitors
```

#### クエリパラメータ

| パラメータ | 型     | 説明                                                                                        |
| ---------- | ------ | ------------------------------------------------------------------------------------------- |
| `status`   | string | フィルタ: `initializing`, `waiting`, `monitoring`, `completed`, `stopped`, `error` |
| `limit`    | int    | 取得件数上限（デフォルト: 50）                                                              |
| `offset`   | int    | オフセット                                                                                  |

#### レスポンス

```json
{
  "monitors": [
    {
      "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
      "stream_url": "https://www.youtube.com/watch?v=XXXXXXXXXXX",
      "status": "monitoring",
      "created_at": "2024-01-15T19:55:00+09:00"
    }
  ],
  "pagination": {
    "total": 15,
    "limit": 50,
    "offset": 0
  }
}
```

### 3.5 エラーレスポンス形式

すべてのAPIエラーは以下の形式で返却される。

```json
{
  "error": {
    "code": "INVALID_URL",
    "message": "The provided stream URL is not a valid YouTube watch URL"
  }
}
```

#### エラーコード一覧

| コード                  | HTTPステータス | 説明                         |
| ----------------------- | -------------- | ---------------------------- |
| `INVALID_URL`           | 400            | 無効なURLが指定された        |
| `INVALID_CONFIG`        | 400            | 設定パラメータが不正         |
| `UNAUTHORIZED`          | 401            | API認証エラー                |
| `MONITOR_NOT_FOUND`     | 404            | 指定された監視IDが存在しない |
| `DUPLICATE_MONITOR`     | 409            | 同一URLの監視が既に存在      |
| `RATE_LIMIT_EXCEEDED`   | 429            | レート制限超過               |
| `MAX_MONITORS_EXCEEDED` | 429            | 最大同時監視数超過           |
| `INTERNAL_ERROR`        | 500            | サーバー内部エラー           |

---

## 4. Webhookコールバック仕様

### 4.1 コールバックイベント一覧

| イベント種別               | 説明                                 |
| -------------------------- | ------------------------------------ |
| `stream.started`           | 配信が開始された                     |
| `stream.ended`             | 配信が終了した                       |
| `stream.delayed`           | 予定時刻を過ぎても配信が開始されない |
| `alert.blackout`           | ブラックアウト（黒画面）を検出       |
| `alert.blackout_recovered` | ブラックアウトから復旧               |
| `alert.silence`            | 無音状態を検出                       |
| `alert.silence_recovered`  | 無音状態から復旧                     |
| `alert.segment_error`      | セグメント取得エラー                 |
| `monitor.error`            | 監視処理でエラー発生                 |

### 4.2 コールバックペイロード

```json
{
  "event_type": "alert.blackout",
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "stream_url": "https://www.youtube.com/watch?v=XXXXXXXXXXX",
  "timestamp": "2024-01-15T20:15:30+09:00",
  "data": {
    "duration_sec": 35,
    "started_at": "2024-01-15T20:14:55+09:00",
    "segment_info": {
      "sequence": 1520,
      "duration": 2.0
    }
  },
  "metadata": {
    "channel_name": "Example Channel",
    "stream_title": "配信タイトル",
    "custom_data": {}
  }
}
```

### 4.3 イベント別データフィールド

#### `stream.delayed`

```json
{
  "scheduled_start_time": "2024-01-15T20:00:00+09:00",
  "delay_sec": 320,
  "tolerance_sec": 300
}
```

#### `alert.blackout` / `alert.silence`

```json
{
  "duration_sec": 35,
  "started_at": "2024-01-15T20:14:55+09:00",
  "threshold_sec": 30,
  "segment_info": {
    "sequence": 1520,
    "duration": 2.0
  }
}
```

#### `alert.blackout_recovered` / `alert.silence_recovered`

```json
{
  "total_duration_sec": 45,
  "started_at": "2024-01-15T20:14:55+09:00",
  "recovered_at": "2024-01-15T20:15:40+09:00"
}
```

### 4.4 コールバックリトライポリシー

| 項目         | 値                                                                        |
| ------------ | ------------------------------------------------------------------------- |
| リトライ回数 | 最大3回                                                                   |
| リトライ間隔 | 指数バックオフ（1秒, 2秒, 4秒）                                           |
| タイムアウト | 10秒                                                                      |
| 成功判定     | HTTP 2xx レスポンス                                                       |
| 失敗時処理   | 全リトライ失敗後、監視ジョブを削除（`monitor.error`イベントは発火しない） |
| Timestamp    | リトライ時も初回生成時の値を保持（変更しない）。これによりイベント発生順序を保証する |

---

## 5. 配信ストリーム取得仕様

### 5.1 ストリームURL取得フロー

```
┌─────────────────────────────────────────────────────────────────┐
│                     ストリームURL取得フロー                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. YouTube URL受信                                              │
│         │                                                        │
│         ▼                                                        │
│  2. yt-dlp / streamlink でマニフェストURL取得                     │
│     ┌─────────────────────────────────────────────┐             │
│     │ yt-dlp --get-url --format "best"            │             │
│     │   https://www.youtube.com/watch?v=XXX       │             │
│     └─────────────────────────────────────────────┘             │
│         │                                                        │
│         ▼                                                        │
│  3. HLS (.m3u8) または DASH (.mpd) マニフェスト取得               │
│         │                                                        │
│         ▼                                                        │
│  4. マニフェスト解析 → セグメントURL抽出                          │
│         │                                                        │
│         ▼                                                        │
│  5. 最新セグメントのみダウンロード → 解析                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 使用ツール

| ツール     | 用途                | 備考                                 |
| ---------- | ------------------- | ------------------------------------ |
| yt-dlp     | マニフェストURL取得 | Goからexec.Commandで呼び出し         |
| streamlink | 代替手段            | yt-dlpが失敗した場合のフォールバック |

### 5.3 yt-dlp実行オプション

```bash
yt-dlp \
  --get-url \
  --format "best[protocol^=http]" \
  --no-playlist \
  --no-warnings \
  --quiet \
  "https://www.youtube.com/watch?v=XXXXXXXXXXX"
```

### 5.4 マニフェスト取得間隔

| 項目             | 値   | 説明                     |
| ---------------- | ---- | ------------------------ |
| 初回取得         | 即時 | 監視開始時               |
| 更新間隔         | 30秒 | マニフェストの再取得間隔 |
| エラー時リトライ | 5秒  | 取得失敗時のリトライ間隔 |

---

## 6. セグメント解析仕様

### 6.1 解析フロー

```
┌─────────────────────────────────────────────────────────────────┐
│                      セグメント解析フロー                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. マニフェストから最新セグメントURL取得                          │
│     (すべてのセグメントを網羅する必要はなく、最新のみで可)          │
│         │                                                        │
│         ▼                                                        │
│  2. セグメントダウンロード（.ts / .m4s）                          │
│         │                                                        │
│         ▼                                                        │
│  3. 映像解析（FFmpeg blackdetect）                                │
│         │                                                        │
│         ▼                                                        │
│  4. 音声解析（FFmpeg silencedetect）                              │
│         │                                                        │
│         ▼                                                        │
│  5. 結果統合・異常判定                                            │
│         │                                                        │
│         ▼                                                        │
│  6. 異常検出時 → Webhook送信                                      │
│         │                                                        │
│         ▼                                                        │
│  7. 次の解析サイクルへ（check_interval_sec待機）                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

※ 各解析処理は順次実行される（並列実行しない）

### 6.2 解析サイクルの実行制御

解析処理が `check_interval_sec` を超過した場合の動作を以下のように定義する。

```
┌─────────────────────────────────────────────────────────────────┐
│                    解析サイクル実行制御                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [解析開始] ──▶ [解析処理中] ──▶ [解析完了]                       │
│       │              │              │                            │
│       │         経過時間 < interval │                            │
│       │              │              ▼                            │
│       │              │     [interval経過まで待機]                │
│       │              │              │                            │
│       │         経過時間 >= interval                             │
│       │              │              │                            │
│       │              ▼              ▼                            │
│       └────────[次のサイクル開始]◀──┘                            │
│                      │                                           │
│             マニフェスト取得 → セグメント取得 → 解析              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| 条件 | 動作 |
| ---- | ---- |
| 解析時間 < check_interval_sec | interval経過まで待機後、次のサイクル開始 |
| 解析時間 >= check_interval_sec | 解析完了後、即座に次のサイクル開始（待機なし） |

※ 解析処理が完了するまで次のマニフェスト取得は行わない（バックプレッシャー制御）

### 6.3 映像解析（ブラックアウト検出）

#### 解析手法

FFmpegの`blackdetect`フィルタを使用し、黒画面を検出する。

```bash
ffmpeg -i segment.ts -vf "blackdetect=d=0.1:pix_th=0.10" -an -f null -
```

#### パラメータ

| パラメータ                   | デフォルト値 | 説明                            |
| ---------------------------- | ------------ | ------------------------------- |
| `d` (duration)               | 0.1          | 最小検出時間（秒）              |
| `pix_th` (pixel threshold)   | 0.10         | 黒と判定する輝度閾値（0.0-1.0） |
| `pic_th` (picture threshold) | 0.98         | フレーム内の黒ピクセル割合閾値  |

#### ブラックアウト判定ロジック

```
if (連続黒画面時間 >= blackout_threshold_sec) {
    → alert.blackout イベント発火
}
if (黒画面状態から復旧) {
    → alert.blackout_recovered イベント発火
}
```

### 6.4 音声解析（無音検出）

#### 解析手法

FFmpegの`silencedetect`フィルタを使用し、無音区間を検出する。

```bash
ffmpeg -i segment.ts -af "silencedetect=n=-50dB:d=0.5" -vn -f null -
```

#### パラメータ

| パラメータ     | デフォルト値 | 説明                   |
| -------------- | ------------ | ---------------------- |
| `n` (noise)    | -50dB        | 無音と判定する音量閾値 |
| `d` (duration) | 0.5          | 最小無音検出時間（秒） |

#### 無音判定ロジック

```
if (連続無音時間 >= silence_threshold_sec) {
    → alert.silence イベント発火
}
if (無音状態から復旧) {
    → alert.silence_recovered イベント発火
}
```

### 6.5 セグメント整合性チェック

| チェック項目         | 説明                               |
| -------------------- | ---------------------------------- |
| セグメント取得可否   | ネットワークエラー・配信終了の検出 |
| セグメント長の妥当性 | 異常に短い/長いセグメントの検出    |

※ シーケンス番号の追跡は行わない（最新セグメントのみを対象とするため）

### 6.6 セグメントエラー発火条件

| 項目         | 値                                                  |
| ------------ | --------------------------------------------------- |
| 失敗継続時間 | 1分間（60秒）                                       |
| 発火イベント | `alert.segment_error`                               |
| 説明         | セグメント取得失敗が1分間継続した場合にイベント発火 |

### 6.7 一時ファイル管理

#### 保存先

```
/tmp/segments/{monitor_id}/
```

#### クリーンアップ

| タイミング   | 動作                                                                                          |
| ------------ | --------------------------------------------------------------------------------------------- |
| 解析完了後   | セグメントファイルを即時削除                                                                  |
| Worker終了時 | ディレクトリごと削除                                                                          |
| 異常終了時   | Kubernetes `emptyDir` ボリュームの使用により、Pod削除に伴い自動的に完全にクリーンアップされる |

---

## 7. 配信開始忘れ検出仕様

### 7.1 Worker動作モード

Workerは配信の状態に応じて以下の2つのモードで動作する。同一Pod内でモード遷移を行う。

```
┌─────────────────────────────────────────────────────────────────┐
│                    Worker動作モード遷移                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [Pod起動] ──▶ [Waiting Mode]                                   │
│                     │                                            │
│          yt-dlpでマニフェスト取得試行                             │
│                     │                                            │
│         ┌──────────┴──────────┐                                 │
│         │                     │                                 │
│    取得成功              取得失敗                                │
│    (is_live=true)        (配信未開始/エラー)                     │
│         │                     │                                 │
│         ▼                     ▼                                 │
│  [Monitoring Mode]    バックオフでリトライ                       │
│  (セグメント解析)           │                                    │
│         │              ┌────┴────┐                              │
│         │         ネットワーク  配信未開始                       │
│         │         エラー        │                               │
│         │              │        ▼                               │
│         │         リトライ  ポーリング継続                       │
│         │              │   (30秒間隔)                           │
│         │              │        │                               │
│         │              └────────┘                               │
│         ▼                                                        │
│    [配信終了検出]                                                │
│         │                                                        │
│         ▼                                                        │
│    [Pod終了]                                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| モード | 状態 | 動作 |
| ------ | ---- | ---- |
| Waiting Mode | 配信未開始 | yt-dlpでマニフェスト取得をポーリング（30秒間隔） |
| Monitoring Mode | 配信中 | セグメント取得・解析を実行（check_interval_sec間隔） |

### 7.2 マニフェスト取得失敗時の挙動

| 失敗理由 | 判定方法 | 対応 |
| -------- | -------- | ---- |
| 配信未開始 | yt-dlpが「Premieres in」「Scheduled for」等を返す | Waiting Modeでポーリング継続 |
| ネットワークエラー | タイムアウト、DNS解決失敗等 | 指数バックオフでリトライ（最大60秒間隔） |
| 動画削除/非公開 | yt-dlpが「Video unavailable」を返す | `monitor.error`を発火しPod終了 |
| 配信終了（アーカイブ） | `is_live=false` | `stream.ended`を発火しPod終了 |

### 7.3 配信開始遅延検出ロジック

```
scheduled_start_time が設定されている場合:

1. 現在時刻が scheduled_start_time を過ぎたかチェック
2. yt-dlpで配信状態を確認（is_liveフィールド）
3. if (配信状態 != "live" && 経過時間 > start_delay_tolerance_sec) {
       → stream.delayed イベント発火
   }

※ 配信終了判定の強化:
yt-dlpのJSON dumpにある `is_live` フィールドを厳密にチェックし、配信ステータスが `live` でない場合は即座に終了（またはエラー）として扱う。アーカイブURLへの誤接続を防ぐ。
```

### 7.4 配信状態の確認方法

#### 方法1: yt-dlp による確認

```bash
yt-dlp --dump-json "https://www.youtube.com/watch?v=XXX" 2>/dev/null | jq '.is_live'
```

#### 方法2: YouTube oEmbed API

```
GET https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=XXX&format=json
```

### 7.5 ポーリング間隔

| 状態           | ポーリング間隔             |
| -------------- | -------------------------- |
| 配信開始前     | 30秒                       |
| 予定時刻超過後 | 10秒                       |
| 配信開始検出後 | セグメント解析モードへ移行 |

### 7.6 配信終了検出とセグメントエラーの判定

監視中（monitoring状態）における配信終了とエラーの判定フローを以下に示す。

#### 判定フローチャート

```
┌─────────────────────────────────────────────────────────────────┐
│              配信終了 / セグメントエラー判定フロー                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [マニフェスト取得試行]                                          │
│         │                                                        │
│    ┌────┴────┐                                                  │
│  成功        失敗                                                │
│    │          │                                                  │
│    ▼          ▼                                                  │
│  [EXT-X-ENDLIST   [リトライ（指数バックオフ）]                   │
│   タグ存在?]            │                                        │
│    │                    │                                        │
│  ┌─┴─┐            失敗継続60秒?                                 │
│ Yes   No                │                                        │
│  │     │           ┌────┴────┐                                  │
│  │     ▼          Yes        No                                  │
│  │  [最新セグメント         │     │                              │
│  │   取得試行]              │  リトライ継続                      │
│  │     │                    │                                    │
│  │  ┌──┴──┐                │                                    │
│  │ 成功   失敗              │                                    │
│  │  │      │                │                                    │
│  │  ▼      ▼                │                                    │
│  │ 解析  リトライ           │                                    │
│  │ 継続  （指数バック       │                                    │
│  │  │    オフ）             │                                    │
│  │  │      │                │                                    │
│  │  │  失敗継続60秒?        │                                    │
│  │  │      │                │                                    │
│  │  │   ┌──┴──┐            │                                    │
│  │  │  Yes    No            │                                    │
│  │  │   │   リトライ        │                                    │
│  │  │   │   継続            │                                    │
│  │  │   ▼                   ▼                                    │
│  │  │  [yt-dlp is_live確認]                                      │
│  │  │         │                                                  │
│  │  │    ┌────┴────┐                                            │
│  │  │  true       false                                          │
│  │  │    │          │                                            │
│  │  │    ▼          │                                            │
│  │  │  [alert.      │                                            │
│  │  │  segment_     │                                            │
│  │  │  error発火]   │                                            │
│  │  │    │          │                                            │
│  │  │    ▼          │                                            │
│  │  │  監視継続     │                                            │
│  │  │  (状態維持)   │                                            │
│  │  │               │                                            │
│  ▼  │               ▼                                            │
│  └──┴──▶ [stream.ended発火]                                     │
│                 │                                                │
│                 ▼                                                │
│          [completed状態へ遷移]                                   │
│                 │                                                │
│                 ▼                                                │
│          [Pod終了]                                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 判定優先順位

| 優先度 | 条件 | 判定結果 | イベント |
| ------ | ---- | -------- | -------- |
| 1 | `EXT-X-ENDLIST`タグ検出 | 配信終了 | `stream.ended` |
| 2 | `is_live=false` | 配信終了 | `stream.ended` |
| 3 | セグメント取得失敗60秒継続 + `is_live=true` | エラー（配信継続中） | `alert.segment_error` |
| 4 | マニフェスト取得失敗60秒継続 + `is_live=true` | エラー（配信継続中） | `alert.segment_error` |

#### 定期的なis_liveチェック

| 項目 | 値 |
| ---- | -- |
| チェック間隔 | 5分 |
| 用途 | 配信終了の補助検出、エラー判定時の配信状態確認 |

#### 終了検出時の動作

```
1. `stream.ended` イベントを発火
2. 監視状態を `completed` に遷移
3. Worker Podを終了
```

---

## 8. 監視Worker仕様

### 8.1 Pod仕様

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: stream-monitor-{monitor_id}  # 例: stream-monitor-mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d
  labels:
    app: stream-monitor
    monitor-id: "{monitor_id}"       # 例: mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d
spec:
  volumes:
    - name: workdir
      emptyDir: {}
  containers:
    - name: monitor
      image: stream-monitor:latest
      volumeMounts:
        - name: workdir
          mountPath: /tmp/segments
      resources:
        requests:
          memory: "256Mi"
          cpu: "100m"
        limits:
          memory: "512Mi"
          cpu: "500m"
      env:
        - name: MONITOR_ID
          value: "{monitor_id}"      # 例: mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d
        - name: STREAM_URL
          value: "{stream_url}"
        - name: CALLBACK_URL
          value: "{callback_url}"
        - name: CONFIG_JSON
          value: "{...}"
        - name: HTTP_PROXY
          value: "{http_proxy}" # Optional
        - name: HTTPS_PROXY
          value: "{https_proxy}" # Optional
  restartPolicy: OnFailure
```

### 8.2 ライフサイクル

```
┌──────────────────────────────────────────────────────────────┐
│                    Worker Podライフサイクル                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  [Created] ─── 初期化 ──▶ [Initializing]                     │
│                               │                               │
│                    yt-dlp実行・マニフェスト取得                │
│                               │                               │
│                    ┌─────────┴─────────┐                     │
│                    │                   │                     │
│                  成功               失敗（yt-dlp等）          │
│                    │                   │                     │
│                    ▼                   ▼                     │
│              [Monitoring]          [Error]                   │
│                    │                   │                     │
│     ┌──────────────┼──────────────┐    │                     │
│     ▼              ▼              ▼    │                     │
│ 配信終了検出   停止API受信    エラー発生 │                     │
│     │              │              │    │                     │
│     ▼              ▼              ▼    │                     │
│ [Completed]    [Stopped]      [Error]  │                     │
│     │              │              │    │                     │
│     └──────────────┴──────────────┴────┘                     │
│                         │                                     │
│                         ▼                                     │
│                  Pod即時削除                                  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 8.3 Graceful Shutdown

Worker Podが停止シグナル（SIGTERM）を受信した際の動作。

| 順序 | 動作                         |
| ---- | ---------------------------- |
| 1    | 新規セグメント取得を停止     |
| 2    | 処理中のセグメント解析を完了 |
| 3    | 未送信のWebhook通知を送信    |
| 4    | 一時ファイルをクリーンアップ |
| 5    | Podを終了                    |

#### タイムアウト

| 項目                          | 値                  |
| ----------------------------- | ------------------- |
| terminationGracePeriodSeconds | 30秒                |
| 強制終了                      | 30秒経過後にSIGKILL |

### 8.4 Pod削除ポリシー

| 項目           | 値                              |
| -------------- | ------------------------------- |
| 削除タイミング | 状態遷移後、即時削除            |
| 対象状態       | `Completed`, `Stopped`, `Error` |

### 8.5 同時監視数制限

| 項目           | 値                                  |
| -------------- | ----------------------------------- |
| 最大同時監視数 | 50件                                |
| 上限超過時     | HTTP 429 (Too Many Requests) を返却 |

### 8.6 Worker → API Gateway 状態同期

WorkerはAPI Gatewayの内部APIを通じて状態を報告する。

#### 内部API エンドポイント

```
PUT /internal/v1/monitors/{monitor_id}/status
```

#### リクエストボディ

```json
{
  "status": "monitoring",
  "health": {
    "video": "ok",
    "audio": "ok"
  },
  "statistics": {
    "total_segments_analyzed": 150,
    "blackout_events": 0,
    "silence_events": 1
  }
}
```

#### 報告タイミング

| イベント | 報告内容 |
| -------- | -------- |
| モード遷移時 | status変更（waiting → monitoring等） |
| セグメント解析完了時 | statistics更新 |
| 異常検出時 | health状態更新 |
| 異常復旧時 | health状態更新 |

#### 認証

| 項目 | 値 |
| ---- | -- |
| 認証方式 | 内部API Key（環境変数 `INTERNAL_API_KEY`） |
| ヘッダ | `X-Internal-API-Key: {key}` |

※ 内部APIはClusterIP Serviceで公開し、外部からはアクセス不可とする

### 8.7 ヘルスチェック

#### エンドポイント

| パス           | 用途              |
| -------------- | ----------------- |
| `GET /healthz` | Livenessプローブ  |
| `GET /readyz`  | Readinessプローブ |

#### プローブ設定

| チェック  | 間隔 | タイムアウト | 失敗閾値 |
| --------- | ---- | ------------ | -------- |
| Liveness  | 30秒 | 5秒          | 3回      |
| Readiness | 10秒 | 5秒          | 3回      |

---

## 9. データストア仕様

### 9.1 PostgreSQL スキーマ

#### monitors テーブル

| カラム名 | 型 | 制約 | 説明 |
| -------- | -- | ---- | ---- |
| id | VARCHAR(37) | PK | `mon-` + UUIDv7形式（DNS-1123準拠、Pod名・API全で統一） |
| stream_url | VARCHAR(512) | NOT NULL | YouTube配信URL |
| callback_url | VARCHAR(512) | NOT NULL | Webhookコールバック先URL |
| config | JSONB | NOT NULL | 監視設定（閾値等） |
| metadata | JSONB | | ユーザー定義メタデータ |
| status | VARCHAR(20) | NOT NULL | initializing/waiting/monitoring/completed/stopped/error |
| pod_name | VARCHAR(63) | | 対応するKubernetes Pod名（例: `stream-monitor-mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d`） |
| created_at | TIMESTAMPTZ | NOT NULL | 作成日時 |
| updated_at | TIMESTAMPTZ | NOT NULL | 更新日時 |

※ idカラムは`mon-`プレフィックス付きで、Pod名・環境変数・APIレスポンスで統一使用。

#### monitor_stats テーブル

| カラム名 | 型 | 制約 | 説明 |
| -------- | -- | ---- | ---- |
| monitor_id | VARCHAR(37) | PK, FK | monitors.id への外部キー |
| total_segments | INT | NOT NULL DEFAULT 0 | 解析済みセグメント数 |
| blackout_events | INT | NOT NULL DEFAULT 0 | ブラックアウト検出回数 |
| silence_events | INT | NOT NULL DEFAULT 0 | 無音検出回数 |
| last_check_at | TIMESTAMPTZ | | 最終チェック日時 |

#### monitor_events テーブル

| カラム名 | 型 | 制約 | 説明 |
| -------- | -- | ---- | ---- |
| id | UUID | PK | UUIDv7形式 |
| monitor_id | VARCHAR(37) | FK, NOT NULL | monitors.id への外部キー |
| event_type | VARCHAR(50) | NOT NULL | イベント種別（stream.started, alert.blackout等） |
| payload | JSONB | NOT NULL | Webhookに送信したペイロード全体 |
| webhook_status | VARCHAR(20) | NOT NULL | pending/sent/failed |
| webhook_attempts | INT | NOT NULL DEFAULT 0 | Webhook送信試行回数 |
| webhook_last_error | TEXT | | 最後のWebhookエラー詳細 |
| created_at | TIMESTAMPTZ | NOT NULL | イベント発生日時 |
| sent_at | TIMESTAMPTZ | | Webhook送信成功日時 |

#### インデックス

```sql
-- monitors
CREATE UNIQUE INDEX idx_monitors_stream_url_active
  ON monitors(stream_url)
  WHERE status IN ('initializing', 'waiting', 'monitoring');

-- monitor_events
CREATE INDEX idx_monitor_events_monitor_id ON monitor_events(monitor_id);
CREATE INDEX idx_monitor_events_created_at ON monitor_events(created_at);
CREATE INDEX idx_monitor_events_webhook_status ON monitor_events(webhook_status)
  WHERE webhook_status = 'pending';
```

---

## 10. エラーハンドリング

### 10.1 エラー分類

| カテゴリ       | エラー例                                  | 対応                    |
| -------------- | ----------------------------------------- | ----------------------- |
| 一時的エラー   | ネットワークタイムアウト、一時的なAPI制限 | 自動リトライ            |
| 永続的エラー   | 無効なURL、削除された動画                 | Webhook通知後、監視停止 |
| システムエラー | OOM、Pod異常終了                          | アラート + 自動再起動   |

### 10.2 リトライポリシー

| 処理             | 最大リトライ | 間隔 | バックオフ       |
| ---------------- | ------------ | ---- | ---------------- |
| マニフェスト取得 | 5回          | 5秒  | 指数（最大60秒） |
| セグメント取得   | 3回          | 2秒  | 指数（最大30秒） |
| Webhook送信      | 3回          | 1秒  | 指数（最大10秒） |

### 10.3 サーキットブレーカー

| 項目                     | 値          |
| ------------------------ | ----------- |
| 失敗閾値                 | 5回連続失敗 |
| オープン状態維持時間     | 30秒        |
| ハーフオープン時の試行数 | 1回         |

### 10.4 Gateway起動時の再整合 (Reconciliation)

API Gatewayが再起動した場合、データベース上の監視状態と実際のKubernetes Podの状態を同期する。この処理は **Idempotent（冪等）** に設計され、何度実行しても安全でなければならない。

#### 実行フロー

1.  **Startup**: Gateway起動時に `ReconcileStartup` フェーズを開始。
2.  **Deadline**: タイムアウト（デフォルト30秒、環境変数 `GATEWAY_RECONCILE_TIMEOUT` で設定可能）を設定。タイムアウト時は処理を中断し、部分的な結果をログ出力して `monitor.error` (reason: reconciliation_timeout) を発火する。
3.  **Snapshot**: DB上の全アクティブ監視 (`status=monitoring`) と、K8s上の全Pod（ラベル `app=stream-monitor`）を取得。
4.  **Reconciliation Actions**:
    - **Missing Pod**: DBで `monitoring` だが Pod がない場合
      - Action: `status=error` に更新し、Webhook通知 (`monitor.error`)。
      - Idempotency: DB更新は `UPDATE ... WHERE status = 'monitoring'` のように現在の状態を確認して行う（CAS的な挙動）。
    - **Zombie Pod**: DBで `stopped` または存在しないが Pod がある場合
      - Action: Podを削除。
      - Idempotency: Pod削除前にラベルと存在確認を行う。既に削除済みの場合は無視する。
    - **Orphaned Pod**: DBにレコードがない Pod がある場合
      - Action: Podを削除。

#### エラーハンドリング

- **一時的エラー (Transient)**:
  - K8s API や DB 接続エラー時は、**指数バックオフ** (Exponential Backoff) を用いてリトライする。
  - リトライ上限を超えた場合、その個別の整合処理はスキップし、エラーログを記録する。
- **非ブロッキング**:
  - 整合処理において永続的なエラーが発生しても、Gateway自体の起動プロセス（HTTPサーバーの開始など）をブロックしてはならない。
  - 全ての整合結果は集約され、最後に「Startup Reconciliation Report」としてログ出力する。

#### Webhook Payload Schema (`monitor.error`)

再整合時に不整合が検出された場合、以下のペイロードでWebhookを送信する。

```json
{
  "event_type": "monitor.error",
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "timestamp": "2024-01-15T20:15:30+09:00",
  "data": {
    "reason": "reconciliation_mismatch",
    "reconciliation_action": "mark_as_error_missing_pod",
    "previous_status": "monitoring",
    "observed_state": {
      "pod_exists": false,
      "db_status": "monitoring"
    },
    "error_details": "Pod not found in Kubernetes cluster during startup reconciliation"
  }
}
```

---

## 11. ログ・メトリクス

### 11.1 ログ設定

| 項目 | 値 | 説明 |
| ---- | -- | ---- |
| デフォルトレベル | `info` | 環境変数 `LOG_LEVEL` で変更可能 |
| 利用可能レベル | debug, info, warn, error | 小文字で指定 |
| 出力形式 | JSON | 構造化ログ |

### 11.2 ログフォーマット

```json
{
  "timestamp": "2024-01-15T20:15:30.123+09:00",
  "level": "INFO",
  "monitor_id": "mon-0190a5c8e4b07d8a9c1d2e3f4a5b6c7d",
  "component": "segment_analyzer",
  "message": "Blackout detected",
  "data": {
    "duration_sec": 35,
    "segment_sequence": 1520
  }
}
```

---

## 12. セキュリティ要件

### 12.1 認証・認可

| 項目        | 要件                                 |
| ----------- | ------------------------------------ |
| API認証     | API Key（環境変数 `API_KEY` で設定） |
| 認証ヘッダ  | `X-API-Key: {api_key}`               |
| Webhook検証 | HMAC-SHA256署名をヘッダに付与        |
| TLS         | 全通信でTLS 1.2以上を必須            |

### 12.2 Webhook署名

#### リクエストヘッダ

```
X-Signature-256: sha256=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
X-Timestamp: 1705315000
```

#### 署名生成アルゴリズム

```
signature = HMAC-SHA256(WEBHOOK_SIGNING_KEY, "{timestamp}.{request_body}")
```

| 項目         | 説明                                           |
| ------------ | ---------------------------------------------- |
| アルゴリズム | HMAC-SHA256                                    |
| 署名キー     | 環境変数 `WEBHOOK_SIGNING_KEY`                 |
| 署名対象     | `{X-Timestampヘッダ値}.{リクエストボディ}`     |
| 出力形式     | `sha256=` + 16進数エンコードされたダイジェスト |

#### 検証例（受信側）

```python
import hmac
import hashlib
import time

def verify_signature(payload: bytes, signature: str, timestamp: str, secret: str) -> bool:
    # リプレイ攻撃対策: タイムスタンプが現在時刻から±5分以内かチェック
    current_time = int(time.time())
    request_time = int(timestamp)
    if abs(current_time - request_time) > 300:  # 5分 = 300秒
        return False

    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.".encode() + payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

#### リプレイ攻撃対策

| 項目 | 値 | 説明 |
| ---- | -- | ---- |
| タイムスタンプ許容範囲 | ±5分（300秒） | リクエスト時刻と現在時刻の差 |
| 検証失敗時 | リクエスト拒否 | HTTP 401 Unauthorizedを返却 |

### 12.3 レート制限

※ 受信側はタイムスタンプが許容範囲外の場合、署名検証前にリクエストを拒否すべき

#### 12.2.1 タイムスタンプの取り扱い

Webhookリクエストには2種類のタイムスタンプが含まれる。それぞれの役割と挙動の違いに注意すること。

| 項目 | 場所 | 値の意味 | リトライ時の挙動 | 用途 |
| ---- | ---- | -------- | ---------------- | ---- |
| `X-Timestamp` | HTTPヘッダ | **送信時刻** | **更新される** | リプレイ攻撃対策、署名検証 |
| `timestamp` | JSONペイロード | **イベント発生時刻** | **維持される** (変更なし) | イベント順序保証、監査ログ |

※ リトライによる再送時、`X-Timestamp` は最新の送信時刻に更新されるが、ペイロード内の `timestamp` はイベントが生成された当初の時刻のまま維持される。

### 12.3 レート制限

| 項目     | 制限値                |
| -------- | --------------------- |
| 監視作成 | 10回/分/クライアント  |
| 状態照会 | 100回/分/クライアント |

---

## 13. 依存関係

### 13.1 外部ツール

| ツール     | バージョン      | 用途              |
| ---------- | --------------- | ----------------- |
| yt-dlp     | 2025.01.15 以上 | ストリームURL取得 |
| FFmpeg     | 7.1 以上        | 映像・音声解析    |
| streamlink | 7.1.0 以上      | フォールバック用  |

### 13.2 外部ツール更新戦略

YouTubeの仕様変更に追従するため、以下の更新戦略を採用する。

| 項目                 | 方針                                                   |
| -------------------- | ------------------------------------------------------ |
| Dockerイメージビルド | CI/CDパイプラインで週次自動ビルド                      |
| yt-dlp               | ビルド時に `pip install --upgrade yt-dlp` で最新版取得 |
| FFmpeg               | ベースイメージ更新時に追従（半年ごと目安）             |
| 緊急対応             | YouTube仕様変更検知時は手動で即時ビルド・デプロイ      |

### 13.3 Goライブラリ

| ライブラリ                 | バージョン | 用途                   |
| -------------------------- | ---------- | ---------------------- |
| `github.com/gin-gonic/gin` | v1.10.0    | HTTPフレームワーク     |
| `github.com/jackc/pgx/v5`  | v5.7.2     | PostgreSQLクライアント |
| `k8s.io/client-go`         | v0.32.0    | Kubernetes API         |
| `go.uber.org/zap`          | v1.27.0    | ロギング               |
| `github.com/grafov/m3u8`   | v0.12.1    | HLSマニフェスト解析    |

---

## 14. デプロイ構成

### 14.1 Helmチャート構成

```
stream-monitor/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── deployment-api.yaml      # API Gateway
│   ├── service.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── serviceaccount.yaml      # Worker Pod作成権限
│   ├── role.yaml
│   ├── rolebinding.yaml
│   └── hpa.yaml                 # API Gatewayのオートスケール
```

### 14.2 環境変数

| 変数名                       | 説明                                              | 必須 |
| ---------------------------- | ------------------------------------------------- | ---- |
| `DB_DSN`                     | PostgreSQL接続文字列                              | ○    |
| `API_KEY`                    | API認証用キー                                     | ○    |
| `WEBHOOK_SIGNING_KEY`        | Webhook署名用キー                                 | ○    |
| `INTERNAL_API_KEY`           | Worker → Gateway内部通信用キー                    | ○    |
| `LOG_LEVEL`                  | ログレベル（debug/info/warn/error）               | -    |
| `MAX_MONITORS`               | 最大同時監視数（デフォルト: 50）                  | -    |
| `HTTP_PROXY` / `HTTPS_PROXY` | `yt-dlp` 使用時のプロキシ設定（IPブロック回避用） | -    |
| `GATEWAY_RECONCILE_TIMEOUT`  | 起動時再整合のタイムアウト（デフォルト: 30秒）    | -    |

### 14.3 RBAC設定

API GatewayがWorker Podを作成・管理するための権限設定。

#### Role定義

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: stream-monitor-gateway
  namespace: stream-monitor  # 権限はこのnamespaceに限定
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "delete", "get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
```

#### RoleBinding定義

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: stream-monitor-gateway
  namespace: stream-monitor
subjects:
  - kind: ServiceAccount
    name: stream-monitor-gateway
    namespace: stream-monitor
roleRef:
  kind: Role
  name: stream-monitor-gateway
  apiGroup: rbac.authorization.k8s.io
```

| 項目 | 値 |
| ---- | -- |
| 権限スコープ | namespace限定（ClusterRoleは使用しない） |
| 対象namespace | `stream-monitor`（デプロイ先namespace） |
| 必要権限 | Pods: create, delete, get, list, watch |

### 14.4 HPA設定（API Gateway）

API Gatewayは基本的にスケールアウト不要だが、将来の拡張に備えHPAを設定する。

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: stream-monitor-gateway
  namespace: stream-monitor
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: stream-monitor-gateway
  minReplicas: 1
  maxReplicas: 3
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

| 項目 | 値 | 説明 |
| ---- | -- | ---- |
| 最小レプリカ数 | 1 | 通常運用時 |
| 最大レプリカ数 | 3 | 負荷増大時 |
| CPUスケール閾値 | 80% | 平均CPU使用率 |
| メモリスケール閾値 | 80% | 平均メモリ使用率 |

※ 想定される監視数（最大50件）では1レプリカで十分処理可能

---

## 15. 今後の拡張検討事項

### 15.1 Phase 2 検討機能

| 機能             | 説明                                         |
| ---------------- | -------------------------------------------- |
| フレーム内容解析 | 特定のシーン（カラーバー、技術画面等）の検出 |
| 音声レベル監視   | 音量が極端に大きい/小さい状態の検出          |
| 字幕監視         | 字幕の有無・内容チェック                     |
| 複数品質監視     | 解像度別のストリーム状態監視                 |

### 15.2 Phase 3 検討機能

| 機能                   | 説明                       |
| ---------------------- | -------------------------- |
| AIベース異常検出       | 機械学習による映像品質評価 |
| 予測アラート           | 過去データに基づく問題予測 |
| マルチプラットフォーム | Twitch、ニコニコ生放送対応 |

---

## 付録A: ステータスコード一覧

| コード | 説明                    |
| ------ | ----------------------- |
| 200    | 成功                    |
| 201    | 監視作成成功            |
| 400    | リクエスト不正          |
| 401    | 認証エラー              |
| 404    | 監視ID不明              |
| 409    | 既に同一URLの監視が存在 |
| 429    | レート制限超過          |
| 500    | サーバー内部エラー      |

## 付録B: 用語集

| 用語           | 説明                                 |
| -------------- | ------------------------------------ |
| マニフェスト   | HLS/DASHの再生リスト（.m3u8 / .mpd） |
| セグメント     | 動画を分割した断片（通常2-10秒）     |
| ブラックアウト | 映像が黒画面になっている状態         |
| 無音           | 音声が閾値以下になっている状態       |

## 付録C: 設計変更履歴 / Design Decisions

### 2026-01-07: 初期レビューに基づく変更

1.  **同時監視数とリソース効率**
    - **決定**: 1配信1Pod構成を維持。最大同時監視数は50件。
    - **理由**: 想定監視数が少数であるため、Pod作成のオーバーヘッドやIP枯渇リスクは許容範囲内。

2.  **セグメント解析の最適化**
    - **決定**: マニフェスト取得後、**最新のセグメントのみ**をダウンロードして解析する。
    - **理由**: 過去のセグメントを網羅的にチェックする必要はなく、リアルタイムの異常検知にフォーカスするため。

3.  **配信終了判定の厳格化**
    - **決定**: `yt-dlp` の `is_live` フィールドをチェックし、ライブ配信中でない場合は即座に監視を停止する。
    - **理由**: 配信終了後にアーカイブURLを誤って監視し続けるのを防ぐため。

4.  **データストアの変更**
    - **決定**: Redisから **PostgreSQL** に変更。
    - **理由**: ユーザー要望による標準化 (Redis -> Postgres)。

5.  **Prometheus削除**
    - **決定**: Prometheusによるメトリクス収集は行わない。
    - **理由**: 不要との判断による。

### 2026-01-07: 追加レビューに基づく変更

6.  **API認証方式**
    - **決定**: 環境変数 `API_KEY` で設定したAPIキーによる認証。
    - **理由**: シンプルな認証方式を採用し、運用負荷を軽減。

7.  **同時監視数上限**
    - **決定**: 最大50件。
    - **理由**: リソース制約とユースケースに基づく適正値。

8.  **Pod削除タイミング**
    - **決定**: 監視終了後、即時削除。
    - **理由**: リソース効率を優先。

9.  **チャンネルURL対応**
    - **決定**: watch URLのみ対応、チャンネルURLは非対応。
    - **理由**: 実装の複雑化を避けるため。

10. **コールバック失敗時の処理**
    - **決定**: 全リトライ失敗後、監視ジョブを削除。
    - **理由**: 無効なWebhook先への継続的な送信を避けるため。

11. **セグメントエラー発火条件**
    - **決定**: 失敗状態が1分間継続した場合に `alert.segment_error` を発火。
    - **理由**: 一時的なネットワーク障害を誤検知しないための猶予時間。

12. **外部ツール更新戦略**
    - **決定**: CI/CDパイプラインで週次自動ビルド、yt-dlpは最新版を取得。
    - **理由**: YouTubeの仕様変更への迅速な対応。

### 2026-01-07: 要件定義書レビューに基づく追加変更

13. **APIエラーレスポンス形式**
    - **決定**: 統一されたエラーレスポンス形式（`error.code`, `error.message`）を定義。
    - **理由**: クライアント側でのエラーハンドリングを容易にするため。

14. **コールバック失敗時のイベント発火**
    - **決定**: 全リトライ失敗後、`monitor.error`イベントは発火せずにジョブを削除。
    - **理由**: コールバック先が無効な場合、エラーイベントも失敗する可能性が高いため。

15. **配信終了検出方法**
    - **決定**: HLSの`EXT-X-ENDLIST`タグ、60秒以上のセグメント更新停止、定期的な`is_live`チェックで検出。
    - **理由**: 複数の検出方法を組み合わせることで確実な終了検出を実現。

16. **一時ファイル管理**
    - **決定**: `/tmp/segments/{monitor_id}/`に保存し、解析完了後に即時削除。
    - **理由**: ディスク容量の効率的な利用とPod削除時の自動クリーンアップ。

17. **Graceful Shutdown**
    - **決定**: SIGTERM受信時、処理中の解析完了・Webhook送信後に終了（タイムアウト30秒）。
    - **理由**: データ整合性の確保と通知の確実な送信。

18. **セグメント解析の実行方式**
    - **決定**: 映像解析・音声解析は順次実行（並列実行しない）。
    - **理由**: 実装のシンプル化とリソース消費の予測可能性を優先。

19. **ライブラリバージョン固定**
    - **決定**: 外部ツール・Goライブラリの推奨バージョンを明示的に指定。
    - **理由**: 再現可能なビルドと予期しない破壊的変更の回避。

### 2026-01-07: 詳細設計レビューに基づく追加変更

20. **解析サイクルの実行制御**
    - **決定**: 解析処理が`check_interval_sec`を超過した場合は待機なしで次のサイクルを開始。解析完了まで次のマニフェスト取得は行わない（バックプレッシャー制御）。
    - **理由**: 処理遅延時の挙動を明確化し、セグメントの取りこぼしを防ぐ。

21. **Worker動作モード**
    - **決定**: Waiting Mode（配信開始待機）とMonitoring Mode（セグメント解析）の2モードを定義。同一Pod内でモード遷移を行う。
    - **理由**: 配信開始前からPodを起動し、シームレスに監視を開始するため。

22. **マニフェスト取得失敗時の挙動**
    - **決定**: 配信未開始/ネットワークエラー/動画削除・非公開を区別し、それぞれ適切な対応を行う。ネットワークエラーは指数バックオフでリトライ。
    - **理由**: エラー種別に応じた適切なハンドリングを実現するため。

23. **monitor_eventsテーブル追加**
    - **決定**: Webhookイベントの履歴を保存するテーブルを追加。送信状態（pending/sent/failed）を管理。
    - **理由**: デバッグ・監査のためのイベント履歴保持。

24. **Worker → API Gateway状態同期**
    - **決定**: Workerは内部API（`PUT /internal/v1/monitors/{monitor_id}/status`）経由でGatewayに状態を報告する。
    - **理由**: 状態管理の一元化とPostgreSQLへの直接接続を避けるため。

25. **セグメントエラーと配信終了の判定フロー**
    - **決定**: 判定優先順位を明確化。EXT-X-ENDLIST > is_live=false > セグメント取得失敗（is_live=trueの場合のみエラー）。
    - **理由**: 配信終了とエラーの誤判定を防ぐため。

26. **Webhook署名のリプレイ攻撃対策**
    - **決定**: タイムスタンプが現在時刻から±5分以内であることを検証。範囲外はリクエスト拒否。
    - **理由**: セキュリティ強化のためのリプレイ攻撃対策。

27. **monitor_id形式（DNS-1123準拠）**
    - **決定**: `mon-` + UUIDv7（ハイフンのみで統一）。Pod名・環境変数・APIレスポンス・Webhookペイロードで全て同一形式を使用。
    - **理由**: KubernetesのDNS-1123制約（ハイフンのみ許可）に準拠し、内外で統一することで、スキーマをシンプル化。UUIDv7のためタイムスタンプ順でソート可能。

28. **ログレベルデフォルト**
    - **決定**: デフォルトは`info`。環境変数`LOG_LEVEL`で変更可能。
    - **理由**: 運用時の適切なログ量を確保。

29. **RBAC設定**
    - **決定**: Role/RoleBindingを使用し、権限をデプロイ先namespace（`stream-monitor`）に限定。ClusterRoleは使用しない。
    - **理由**: 最小権限の原則に従い、セキュリティリスクを軽減。

30. **HPA設定**
    - **決定**: CPU/メモリ80%でスケール。最小1レプリカ、最大3レプリカ。想定監視数では1レプリカで十分。
    - **理由**: 将来の拡張に備えつつ、通常運用でのリソース効率を確保。

31. **シーケンス番号追跡**
    - **決定**: シーケンス番号の追跡は行わない（最新セグメントのみを対象）。
    - **理由**: リアルタイム監視において過去セグメントの網羅は不要。
