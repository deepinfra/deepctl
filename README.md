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
...
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
