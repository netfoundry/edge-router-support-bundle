# edge-router-support-bundle

NetFoundry support bundle

  This script was intended to be used on the 
  netfoundry edge-router image created &
  maintained by netfoundry.

## Build

The main script should be created locally & checked into the source repository.

The create the distribution package

Export the correct values:
* AWS_BUCKET_NAME
* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY

```
pip install -r requirements
pyinstaller -F support_bundle.py
```

