# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.3] - 2024-03-26
### Added

- Added diverter commands and file to bundle

## [1.4.2] - 2024-03-20
### Added

- Added new flag do not upload flag `-l`

## [1.4.1] - 2023-12-27
### Changed

- Fixed issue with defining host_id
- Fixed issue with certificate paths

## [1.4.0] - 2023-12-13
### Changed

- Removed sys_info file & merged it into the info_file in json format.
- Added section to extract ziti router id from local certificate.


## [1.3.4] - 2023-11-13
### Changed

- Added /usr/lib/systemd/resolved.conf.d/01-ziti.conf to list of gathered files.

## [1.3.3] - 2023-11-08
### Changed

- Added prefix "nf-" to tempdir

## [1.3.2] - 2023-11-02
### Changed

- Added router registration log to gathered files.

## [1.3.1] - 2023-11-01
### Changed

- Added salt-minion to journal command output list.

## [1.3.0] - 2023-10-04

### Changed

- Changed extracting path of pyinstaller from /tmp to /opt/netfoundry


## [1.2.1] - 2023-03-20
### Changed:

    - Fixed bug in info file function

## [1.2.0] - 2023-02-23
### Changed:

    - Changd process lookup to handle single binary deployments
    - Clean up info file function

## [1.1.0] - 2023-01-27
### Added:

    - CPU dumps 
 

## [1.0.0] - 2023-01-09

    - Initial Release