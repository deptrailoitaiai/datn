const { app, BrowserWindow, Menu, ipcMain } = require('electron');
const path = require('path');
const isDev = process.env.NODE_ENV === 'development';

// Keep window references
let mainWindow = null;
let loginWindow = null;
let serverProcess = null;

// Check if server is already running
async function checkServerRunning() {
    const http = require('http');
    
    return new Promise((resolve) => {
        const req = http.get('http://localhost:3000', (res) => {
            resolve(true);
        });
        
        req.on('error', () => {
            resolve(false);
        });
        
        req.setTimeout(1000, () => {
            req.abort();
            resolve(false);
        });
    });
}

// Start the chat server
async function startServer() {
    const isRunning = await checkServerRunning();
    
    if (isRunning) {
        console.log('Server is already running on port 3000');
        return Promise.resolve();
    }
    
    const { spawn } = require('child_process');
    const path = require('path');
    
    // Handle different execution contexts (dev vs AppImage)
    let serverPath, workingDir;
    
    if (app.isPackaged) {
        // In packaged app, server.js is in resources/app.asar
        serverPath = path.join(process.resourcesPath, 'app.asar', 'server.js');
        workingDir = path.join(process.resourcesPath, 'app.asar');
    } else {
        // In development
        serverPath = path.join(__dirname, 'server.js');
        workingDir = __dirname;
    }
    
    console.log('Starting server from:', serverPath);
    
    try {
        serverProcess = spawn('node', [serverPath], {
            cwd: workingDir,
            stdio: 'inherit'
        });
        
        serverProcess.on('error', (error) => {
            console.error('Failed to start server:', error);
            console.log('App will continue without embedded server');
            // App will use external server if available
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        console.log('App will continue without embedded server');
        // App will use external server if available
    }
    
    serverProcess.on('exit', (code, signal) => {
        if (code !== null && code !== 0) {
            console.log(`Server process exited with code ${code}`);
        }
    });
    
    // Give server time to start
    return new Promise(resolve => setTimeout(resolve, 2000));
}

// Create login window
function createLoginWindow() {
    loginWindow = new BrowserWindow({
        width: 400,
        height: 500,
        minWidth: 350,
        minHeight: 450,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        resizable: true,
        maximizable: true,
        fullscreenable: true,
        center: true,
        title: 'P2P Encrypted Chat - Login'
    });

    loginWindow.loadFile(path.join(__dirname, 'public', 'login.html'));

    if (isDev) {
        loginWindow.webContents.openDevTools();
    }

    loginWindow.on('closed', () => {
        loginWindow = null;
    });
}

// Create main chat window
function createMainWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        minWidth: 800,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        center: true,
        title: 'P2P Encrypted Chat',
        resizable: true,
        maximizable: true,
        fullscreenable: true,
        show: false
    });
    
    // Show window when ready and maximize it
    mainWindow.once('ready-to-show', () => {
        mainWindow.maximize();
        mainWindow.show();
    });

    mainWindow.loadURL('http://localhost:3000');

    // Pass user data to main window when ready
    mainWindow.webContents.once('did-finish-load', () => {
        if (global.sharedUserData) {
            mainWindow.webContents.send('set-user-data', global.sharedUserData);
        }
    });

    if (isDev) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// Create application menu
function createMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Logout',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.close();
                            createLoginWindow();
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                    click: () => {
                        app.quit();
                    }
                }
            ]
        },
        {
            label: 'View',
            submenu: [
                { role: 'reload' },
                { role: 'forceReload' },
                { role: 'toggleDevTools' },
                { type: 'separator' },
                { role: 'resetZoom' },
                { role: 'zoomIn' },
                { role: 'zoomOut' },
                { type: 'separator' },
                { role: 'togglefullscreen' }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'About',
                    click: () => {
                        const { dialog } = require('electron');
                        dialog.showMessageBox(mainWindow || loginWindow, {
                            type: 'info',
                            title: 'About P2P Encrypted Chat',
                            message: 'P2P Encrypted Chat v1.0.0',
                            detail: 'Secure peer-to-peer chat application with hybrid encryption.'
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

// Handle login success
ipcMain.on('login-success', (event, userData) => {
    console.log('Login successful:', userData);
    
    // Store user data globally to pass to main window
    global.sharedUserData = userData;
    
    if (loginWindow) {
        loginWindow.close();
    }
    createMainWindow();
});

// Handle login window ready
ipcMain.on('login-window-ready', () => {
    console.log('Login window ready');
});

// App event handlers
app.whenReady().then(async () => {
    console.log('🚀 Starting P2P Encrypted Chat Desktop App...');
    
    // Try to start the server, but don't fail if it doesn't work
    try {
        await startServer();
    } catch (error) {
        console.error('Failed to start server:', error);
        console.log('App will continue without embedded server');
    }
    
    // Create menu
    createMenu();
    
    // Show login window
    createLoginWindow();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        // Kill server process
        if (serverProcess) {
            serverProcess.kill();
        }
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createLoginWindow();
    }
});

app.on('before-quit', () => {
    // Kill server process
    if (serverProcess) {
        serverProcess.kill();
    }
});

// Handle app termination
process.on('SIGINT', () => {
    if (serverProcess) {
        serverProcess.kill();
    }
    app.quit();
});

process.on('SIGTERM', () => {
    if (serverProcess) {
        serverProcess.kill();
    }
    app.quit();
});