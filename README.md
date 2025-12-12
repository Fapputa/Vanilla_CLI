# **Vanilla_CLI**

**Vanilla_CLI** is a versatile and lightweight command-line tool suite designed to enhance your Linux terminal experience. New tools and commands are regularly added to the suite, making it an ever-evolving productivity environment.  

---

## **Features**

- **Modular Command Suite**  
  Includes commands like `clip`, `compil`, and more, allowing for more flexible command-line operations.

- **Abyss – CLI Code Editor**  
  - Supports **C, C++, C#, Python, HTML, CSS, JSON, SQL, Shell, and Assembly**.  
  - Automatic compilation based on file extension.  
  - Real-time compilation and execution preview.  
  - Split-screen interface: left side for code, right side for output.  
  - Live HTML preview served on `localhost`.  

- **Keyboard Shortcuts**  
  - `Ctrl + K` – Delete a line  
  - `Ctrl + N` – Split the screen into two  
  - `Ctrl + X` – Exit  
  - `Ctrl + O` – Save As  
  - `Ctrl + B` – Compile / Execute  

- **Lightweight & Portable**  
  Optimized for speed and minimal system impact.  

- **Syntax Highlighting & Autocompletion**  
  - Supports color-coded syntax (e.g., `#include` in orange, comments in grey).  
  - Smart autocompletion: transforms patterns like  
    ```c
    () {printf("test"); 
    ```  
    into  
    ```c
    {
        printf("test");
    }
    ```  
  - HTML tags and other languages are also supported.  

---

## **Installation**

1. Copy all files into your `~/bin/` folder:
   ```bash
   cd Vanilla_CLI
   sudo chmod +x **
   sudo mv ** /home/$USER/bin/

   ```

