[![Commits Verified](https://img.shields.io/badge/commits-verified-brightgreen)](https://github.com/Kaidevon/memscan/commits/master)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0.html)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://www.kernel.org/)
[![C](https://img.shields.io/badge/C-99-blue)](https://gcc.gnu.org/)

# memscan

A memory scanner running on Linux / Android.

## About

This project is a memory scanning tool for Linux and Android platforms, with multithreading support.

## Features

- Supports Linux and Android platforms
- Multithreaded parallel scanning
- Fast scanning for large memory regions
- Clear structure, easy to extend with new scanning modes
- Uses the LGPLv3 license, ensuring software freedom

## Supported Platforms

- Linux
- Android

## Build

```bash
git clone <repository-url>
cd <project>
make -j$(nproc)
```

Or

```
ndk-build
```

This project uses Android NDK 21.

## Usage

For developers; please refer to the code for details.

## Design Highlights

- **Progress visualization** Progress visualization
- **Multithreaded scanning** Good task distribution
- **Performance first** Performance first
- **Cross-platform** Supports Linux and Android

## Acknowledgments

The design of this project uses **libelf**. Thanks to the open-source community for the tools and documentation provided.

## License

This library is released under the **GNU Lesser General Public License v3.0 (LGPLv3)**.

You may link it into your own programs, including proprietary ones, under the terms of LGPLv3. Modifications to the library itself must be shared under the same license. For the complete license text, see the `LICENSE` and `COPYING.LESSER` files in the project root directory.

## Contact

Email: kaidevonmail@gmail.com

## Author

Author: kaidev