# ElevenLabs Voice Cloning Workflow Guide

다국어 데모 영상 (영어 / 한국어 / 일본어) 합성 작업 가이드.

## 작업 시간 예상

- ElevenLabs 가입 + 음성 클로닝: **10분**
- 18개 MP3 합성 (3 언어 × 6 scenes): **15분**
- MP3 업로드 → 영상 합성 (Claude): **자동**

## 시퀀스

### Step 1 — ElevenLabs 가입

1. https://elevenlabs.io/sign-up 접속
2. 이메일 / Google 계정으로 가입
3. **Free tier** 선택 (월 10,000 character 무료)

### Step 2 — Instant Voice Cloning

1. 좌측 메뉴 → **Voices**
2. **Add a new voice** → **Instant Voice Cloning**
3. Voice name: `Bang Juwon` 또는 `Yushin`
4. **Files**: 새로운_녹음.m4a 업로드
5. Labels (선택):
   - gender = male
   - accent = korean
   - age = middle aged
   - description = "calm, professional, technical narrator"
6. **Add Voice** 클릭 → 즉시 클로닝 완료

### Step 3 — 합성 (Speech Synthesis)

좌측 메뉴 → **Speech Synthesis** 진입.

설정:
- **Voice** = Bang Juwon (방금 만든 거)
- **Model** = `eleven_multilingual_v2` (이게 중요 — 한/일/영 모두 지원)
- **Voice Settings**:
  - Stability: 50% (안정성 + 자연스러움 균형)
  - Similarity: 75% (본인 음성 유사도)
  - Style: 0% (중립적 톤)
  - Speaker boost: ON

각 scene 텍스트를 입력 박스에 붙여넣고 → **Generate** → MP3 다운로드.

### Step 4 — 파일 명명 + 정리

다운로드한 MP3를 다음 이름으로 정리:

```
en/scene1.mp3 ... en/scene6.mp3   (영어 6개)
ko/scene1.mp3 ... ko/scene6.mp3   (한국어 6개)
ja/scene1.mp3 ... ja/scene6.mp3   (일본어 6개)
```

→ 총 **18개 MP3 파일**

### Step 5 — 업로드

폴더 통째로 ZIP 압축 → Claude에 업로드 → 영상 자동 합성 + 첨부.

## Tip — Character 절약

총 character 예상:
- 영어: ~2,200 char
- 한국어: ~1,800 char
- 일본어: ~1,500 char
- **합계 ~5,500 char** (무료 10,000 char 충분)

만약 동일 텍스트를 두 번 generate 했다가 마음에 안 들어 다시 생성 시 character 누적 — 한 번에 generate하시는 게 절약.

## Tip — 자연스러움 극대화

ElevenLabs는 **마침표(period)** 와 **쉼표(comma)** 를 자동으로 호흡으로 해석합니다.
scene 텍스트는 이미 짧은 호흡 단위로 마침표 박혀있으니, 그대로 붙여넣으면 자연 호흡 톤으로 나옵니다.

만약 더 긴 휴식이 필요하면 텍스트에 줄바꿈 2개 (단락 구분) 넣으십시오.
