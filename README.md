# edge-router-support-bundle

NetFoundry support bundle

  This script was intended to be used on the 
  netfoundry edge-router image created &
  maintained by netfoundry.

## Build

The main script should be created locally & checked into the source repository.

To create the package with pyinstaller you need to pass in a `--runtime-hook` to setup the os.eviron variables.

Example, create a file called local_build.py
```
import os
os.environ['AWS_BUCKET_NAME'] = <your bucket name>
os.environ['AWS_ACCESS_KEY_ID'] = <your key id>
os.environ['AWS_SECRET_ACCESS_KEY'] = <your secret>
```
Then you can build:
```
pip install -r requirements
pyinstaller -F support_bundle.py --runtime-hook local_build.py
```

