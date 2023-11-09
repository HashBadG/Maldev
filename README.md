<a name="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">  
<h3 align="center">Yarnham</h3>
  <p align="center">
    This project aims to discover the world of Malware Development.
    <br />
    <a href="https://github.com/HashBadG/Maldev/issues">Report Bug</a>
    ·
    <a href="https://github.com/HashBadG/Maldev/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    </li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This is a personal project designed to immerse me in the world of malware development. This will enable me to gain a better understanding of how malware works, and to learn more about operating systems.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

In the various folders present in this directory, you'll discover some C code enabling you to perform malicious actions. Each part will be documented, enabling you to compile and use the code.

### Prerequisites

The prerequisites are as follows:
- A Windows 10 virtual machine.
- A compiler such as CL.
- Windows Defender disabled on the machine to avoid being flagged.

### Installation

To install, simply clone the directory and use make to compile the code. (see the Makefile for more details). Here is the detailed steps :
1. Open the `x64 Native Tools Command Prompt for VS 2022` installed with [VS Tools](https://aka.ms/vs/17/release/vs_BuildTools.exe)

2. Clone the repository and navigate to it
```cmd
cd Maldev
```

3. Use the make command to compile the malicious code:
```bash
make malicious
```

4. You can clean the code using the `clean` command with Make:
```
make clean
```

<!-- USAGE EXAMPLES -->
## Usage

All the details will be provided in a different documentation with this form `DOCS_<code>.md`

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

HashBadG - [@H4shB](https://twitter.com/H4shB)

Project Link: [https://github.com/HashBadG/Maldev](https://github.com/HashBadG/Maldev)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[contributors-shield]: https://img.shields.io/github/contributors/HashBadG/Maldev.svg?style=for-the-badge
[contributors-url]: https://github.com/HashBadG/Maldev/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/HashBadG/Maldev.svg?style=for-the-badge
[forks-url]: https://github.com/HashBadG/Maldev/network/members
[stars-shield]: https://img.shields.io/github/stars/HashBadG/Maldev.svg?style=for-the-badge
[stars-url]: https://github.com/HashBadG/Maldev/stargazers
[issues-shield]: https://img.shields.io/github/issues/HashBadG/Maldev.svg?style=for-the-badge
[issues-url]: https://github.com/HashBadG/Maldev/issues
[license-shield]: https://img.shields.io/github/license/HashBadG/Maldev.svg?style=for-the-badge
[license-url]: https://github.com/HashBadG/Maldev/blob/master/LICENSE.txt