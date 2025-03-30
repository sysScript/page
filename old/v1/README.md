# V: 1.0

All "Pull Requests" are accepted.

---

# SystemScript IDE

A professional-grade development environment for the SystemScript programming language.

## Features

- **Modern Code Editor**
  - Syntax highlighting for SystemScript
  - Line numbering
  - Auto-indentation and brace matching
  - Multiple tabs for open files

- **Project Management**
  - File explorer
  - Recent files tracking
  - Project organization

- **Build System Integration**
  - Compile SystemScript files
  - Run and debug applications
  - Build output console

- **Professional UI**
  - Dark and light themes
  - Customizable interface
  - Dock-based layout

## Requirements

- Python 3.6+
- PyQt5
- QScintilla (included in PyQt5)


## ssIDE Usage

### Creating a new file

1. Click **File → New** or press **Ctrl+N**
2. Start coding in SystemScript

### Opening an existing file

1. Click **File → Open** or press **Ctrl+O**
2. Browse to your SystemScript file (.ss extension)
3. Select the file and click Open

### Saving files

- To save: Click **File → Save** or press **Ctrl+S**
- To save as a new file: Click **File → Save As** or press **Ctrl+Shift+S**

### Building and running

1. Open a SystemScript file
2. Click **Build → Build** or press **F7** to compile
3. Click **Build → Run** or press **F5** to run the program
4. For a one-step process, use **Build → Build and Run** (Ctrl+F5)

### Switching themes

1. Go to **View → Theme**
2. Select either **Light** or **Dark**
3. Restart the application for the theme to fully apply

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| New File | Ctrl+N |
| Open File | Ctrl+O |
| Save | Ctrl+S |
| Save As | Ctrl+Shift+S |
| Close Tab | Ctrl+W |
| Exit | Alt+F4 |
| Undo | Ctrl+Z |
| Redo | Ctrl+Y |
| Cut | Ctrl+X |
| Copy | Ctrl+C |
| Paste | Ctrl+V |
| Select All | Ctrl+A |
| Build | F7 |
| Run | F5 |
| Build & Run | Ctrl+F5 |

## Configuration

The IDE settings are stored in `~/.systemscript-ide/config.json`. This file contains your preferences including:

- Window size and position
- Editor settings
- Recent files
- Theme preference
- Compiler settings

## License

This project is licensed under [Creative Commons Attribution-NonCommercial-NoDerivs 4.0 International] – see [CPScript/Legal](https://github.com/CPScript/Legal) for details.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

SystemScript IDE © 2025. All rights reserved.
