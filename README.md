# TightSecure — Password Security Assistant

An elegant, high-performance, single-page application (SPA) designed to evaluate password strength using nine detailed security metrics. Built as a mini-project for B.Sc. IT, it utilizes only standard client-side languages (HTML5, CSS3, Vanilla JavaScript) without external libraries, backend servers, or databases.

---

## 🚀 Features

- **9-Metric Analysis Check**: Analyzes passwords for length, uppercase/lowercase variety, number and special character density, repetition patterns, common dictionary words, common keyboard layouts, and Shannon entropy.
- **Robust Scoring System**: Scores are calculated out of a maximum of 100 points, classifying results into 4 distinct security brackets.
- **Glassmorphic UI**: High-end modern styling featuring deep slate background color `#0F172A`, floating glass cards, smooth transition keyframes, and neon glows.
- **Secure On-Demand Generator**: Provides a secure password generator using `window.crypto.getRandomValues` to output cryptographically random strings.
- **Local Storage Statistics**: Tracks historical scans, showing total passwords checked, average score, and strength distribution.
- **Responsive Layout**: Designed to adapt perfectly to mobile viewports, tablets, and large displays.

---

## 📈 Scoring Rules

The application allocates points based on the following breakdown:

| Metric | Condition | Points |
| :--- | :--- | :---: |
| **Length** | 12 or more characters | 20 |
| **Uppercase** | Contains at least 1 uppercase letter (`A-Z`) | 10 |
| **Lowercase** | Contains at least 1 lowercase letter (`a-z`) | 10 |
| **Numbers** | Contains at least 1 numerical digit (`0-9`) | 10 |
| **Symbols** | Contains at least 1 special character (e.g. `!@#$`) | 15 |
| **No Repeats** | No consecutive repeated characters (e.g. `aa`) | 10 |
| **No Sequences** | No simple alphabetical/numeric or keyboard sequences | 10 |
| **Not Common** | Password is not in the built-in common password list | 15 |
| **Entropy** | Shannon character entropy value is $\ge 3.0$ bits | 10 |
| **Total** | | **100** |

---

## 🗂 File Structure

The project directory is structured as follows:

```text
ProjectFolder/
  ├── index.html          # Main entry point HTML5 document
  ├── package.json        # NPM dependencies and scripts
  ├── vercel.json         # Vercel deployment configuration
  ├── src/
  │   ├── css/
  │   │   ├── style.css       # Core styles and design tokens
  │   │   ├── responsive.css  # Mobile and tablet responsiveness rules
  │   │   └── animations.css  # Keyframe animations and transitions
  │   ├── js/
  │   │   ├── utils.js        # Helper utility functions
  │   │   ├── analyzer.js     # Password strength scoring engine
  │   │   ├── generator.js    # Cryptographically secure generator
  │   │   ├── statistics.js   # Session metrics & local storage manager
  │   │   └── app.js          # Main entry module & coordinator
  │   └── assets/
  │       ├── images/         # Image assets
  │       ├── icons/          # Icon assets
  │       └── screenshots/    # Application demo screenshots
  └── README.md           # Project documentation
```

---

## ⚙️ How to Run

This project uses **Vite** for local development and bundling.

### Prerequisites

Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

### Local Development

1. Clone or download this project.
2. Install the dependencies:
   ```bash
   npm install
   ```
3. Start the local development server:
   ```bash
   npm run dev
   ```
4. Open the displayed URL (typically `http://localhost:5173`) in your browser.

### Production Build

To build the static files for production deployment:
```bash
npm run build
```
This generates optimized static files in the `dist/` directory.

### Preview Build

To preview the built production app locally:
```bash
npm run preview
```

---

## 🔒 Security Focus

- **No Network Requests**: All analyses and password generation happen entirely client-side inside the user's browser. Passwords never traverse the internet.
- **Cryptographic Randomness**: The password generator utilizes the browser's Web Crypto API (`window.crypto.getRandomValues`) to guarantee that generated sequences are mathematically hard to predict.
