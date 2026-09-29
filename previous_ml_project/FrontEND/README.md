# ClickSafe - Phishing Detection App

A production-ready React frontend for detecting and reporting phishing/scam websites.

## Features

- 🔐 User login with mobile number validation (India)
- 🛡️ URL safety checker with confidence scoring
- 🚩 Report suspicious URLs
- 📊 Scan history tracking
- 📱 Fully responsive design
- ♿ WCAG AA accessible
- 🎨 Modern, clean UI with Tailwind CSS

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast development
- **Tailwind CSS** for styling
- **React Router DOM** for navigation
- **Axios** for API calls
- **React Hook Form** for form handling
- **Zustand/Context** for state management

## Getting Started

### Prerequisites

- Node.js 18+ and npm

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run linter
npm run lint
```

## Environment Variables

Create a `.env` file in the root directory:

```env
# Optional: Set to use real backend API instead of mock
VITE_API_BASE_URL=https://your-api-server.com
```

If `VITE_API_BASE_URL` is not set, the app will use the built-in mock API for development.

## API Integration

The app expects two backend endpoints:

### POST /predict
Check if a URL is safe or a scam.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "label": "safe" | "scam",
  "confidence": 0.92,
  "rules": ["no_https", "url_shortener"],
  "explanation": ["Contains url shortener", "No https"]
}
```

### POST /report
Report a suspicious URL.

**Request:**
```json
{
  "url": "https://suspicious-site.com",
  "reporter": "9876543210",
  "notes": "Optional notes"
}
```

**Response:**
```json
{
  "ok": true,
  "id": "report_uuid"
}
```

## Project Structure

```
src/
├── components/          # React components
│   ├── Header.tsx      # App header with profile/logout
│   ├── CheckCard.tsx   # URL checker widget
│   ├── ReportCard.tsx  # URL reporter widget
│   ├── ResultModal.tsx # Scan result display
│   └── HistoryPanel.tsx# Scan history
├── pages/              # Route pages
│   ├── LoginPage.tsx   # Login/signup page
│   └── DashboardPage.tsx # Main dashboard
├── contexts/           # React contexts
│   └── AuthContext.tsx # Authentication state
├── services/           # API services
│   ├── api.ts         # API client and functions
│   └── mockApi.ts     # Mock API for development
├── lib/               # Utilities
│   └── validators.ts  # Input validation functions
└── types.ts           # TypeScript type definitions
```

## Development Notes

### Mock API
The app includes a mock API (`src/services/mockApi.ts`) that simulates backend responses. It provides:
- Deterministic results based on URL hash
- Realistic network delays
- Random confidence scores and rule matches

### Local Storage
The app uses localStorage for:
- User authentication (`clicksafe_user`)
- Scan history (`clicksafe_history`)

### Adding Backend Integration
To connect to a real backend:

1. Set `VITE_API_BASE_URL` environment variable
2. Ensure backend implements the `/predict` and `/report` endpoints
3. The app will automatically switch from mock to real API

### Future Enhancements
- OTP-based authentication
- Backend history sync
- Advanced reporting with screenshots
- Rate limiting on backend
- Real-time threat intelligence updates

## Deployment

### Vercel
```bash
npm run build
vercel --prod
```

### Netlify
```bash
npm run build
netlify deploy --prod --dir=dist
```

## Accessibility

- All interactive elements are keyboard accessible
- Semantic HTML throughout
- ARIA labels and roles
- Focus management in modals
- Color contrast meets WCAG AA standards
- Screen reader friendly form validation

## License

MIT

## Support

For issues and questions, please open a GitHub issue.
