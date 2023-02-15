# deepctl
Command line tool for [Deep Infra cloud ML inference service](https://deepinfra.com/).

## Installation

#### Linux, MacOS

```bash
curl https://deepinfra.com/get.sh | sh
```

#### Download from Github

You can also download deepctl from [Releases](https://github.com/deepinfra/deepctl/releases).

## Usage

#### Sign in
You need a Github account to use deepctl. This command will open your Github Sign-on page in your browser. Follow instructions there.
```bash
deepctl auth login
```
#### View your Deep Infra API auth token to use it in your applications
```bash
deepctl auth token
```

#### List supported models
```bash
deepctl model list
```

#### Create a model deployment
```bash
deepctl deploy create -m openai/whisper-small
```

#### Inference
To get information about model, it's inference arguments, response fields and ways to call endpoint, use the following command:
```bash
deepctl model info -m openai/whisper-small
```
Output:
```
model: openai/whisper-small
type: automatic-speech-recognition
CURL invocation:

 curl -X POST \
    -H "Authorization: bearer $AUTH_TOKEN"  \
    -F audio=@my_voice.mp3  \
    'https://api.deepinfra.com/v1/inference/openai/whisper-small'

deepctl invocation:

 deepctl infer \
    -m 'openai/whisper-small'  \
    -i audio=@my_voice.mp3

Field description:

parameters:
  audio     : binary. sound file bytes in supported format (mp3, flac)
  task      : (Default: 'transcribe') string. task to perform
  language  : (Default: None) string. language that the audio is in; uses detected language if None
  temperature: (Default: 0.0) number. temperature to use for sampling
  patience  : (Default: 1.0) number. patience value to use in beam decoding
  suppress_tokens: (Default: '-1') string. token ids to suppress during sampling
  initial_prompt: (Default: None) string. optional text to provide as a prompt for the first window.
  condition_on_previous_text: (Default: True) boolean. provide the previous output of the model as a prompt for the next window
  temperature_increment_on_fallback: (Default: 0.2) number. temperature to increase when falling back when the decoding fails to meet either of the thresholds below
  compression_ratio_threshold: (Default: 2.4) number. gzip compression ratio threshold
  logprob_threshold: (Default: -1) number. average log probability threshold
  no_speech_threshold: (Default: 0.6) number. probability of the <|nospeech|> token threshold

send the parameters as EITHER:
- JSON object (one key: value per parameter, binary as base64 or Data URL)
- HTTP multipart (one part per parameter).


output example:

{
  "text": "",
  "segments": [
    {
      "id": 0,
      "text": "Hello",
      "start": 0.0,
      "end": 1.0
    },
    {
      "id": 1,
      "text": "World",
      "start": 4.0,
      "end": 5.0
    }
  ],
  "language": "en"
}


output fields description:

text: string. transcription
segments: array[Segment]. a list of timestamped pieces
Segment fields:
    id: integer. segment id
    seek: integer. 
    start: number. start location in input in seconds from start
    end: number. end location in input in seconds from start
    text: string. a piece of the decoded text
    tokens: array[integer]. a list of tokens in the segment
    temperature: number. temperature of the segment
    avg_logprob: number. 
    compression_ratio: number. compression ratio of the segment
    no_speech_prob: number. probability of no speech in the segment
language: string. language of audio
```
When using HTTP inference api make sure to pass your AUTH_TOKEN header.
```bash
curl -X POST \
    -H "Authorization: bearer $AUTH_TOKEN"  \
    -F audio=@/path/to/hello_world.mp3  \
    'https://api.deepinfra.com/v1/inference/openai/whisper-small'
```
Output:
```
{"text":" Hello world"}
```

#### List your deployments
```bash
deepctl deploy list
```
Output:
```
[
  {
    "created_at": "2023-01-26T19:33:23",
    "deploy_id": "DpM4BkrjEspUwmTa",
    "fail_reason": "",
    "model_name": "openai/whisper-small",
    "status": "running",
    "task": "automatic-speech-recognition",
    "updated_at": "2023-01-26T19:33:23"
  }
]
```

#### Delete deployment
Use deploy_id from the output above to delete the deployment.
```bash
deepctl deploy delete DpM4BkrjEspUwmTa
```

#### More information
You can always use
```bash
deepctl help
```
to view more information on any command.

## Check version and update
```bash
deepctl version check
deepctl version update
```
