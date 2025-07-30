# OpenVPN Tool

A Zig-based tool for managing OpenVPN credentials with encryption and NetworkManager integration.

## Prerequisites

- Zig compiler
- GIO development libraries (on Ubuntu/Debian: `sudo apt install libgio2.0-dev`)

## Building

To build the project:

```bash
zig build
```

## Running

To run the tool:

```bash
zig build run
```

Or build and run in one step:

```bash
zig build run
```

## Features

- Encrypted credential storage using AES-256-GCM
- TOTP secret support
- NetworkManager D-Bus integration
- Secure password input (no echo)

## Project Structure

```
openvpn/
├── build.zig      # Build configuration
├── openvpn.zig    # Main source code
└── README.md      # This file
```

## Dependencies

The project links against:
- `gio-2.0` - GIO library for D-Bus communication
- `gobject-2.0` - GObject library
- `glib-2.0` - GLib library
- `pthread` - POSIX threads 