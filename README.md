# ShareBari Server

Single-file TypeScript Express backend for ShareBari.

ShareBari is a hyperlocal item sharing and rental marketplace. This server will provide authentication, rental item APIs, dashboard data, contact messages, and Stripe checkout support as the project phases progress.

## Backend Entry

The backend entry file is:

```text
index.ts
```

Do not replace it with `index.js`; TypeScript is mandatory for the backend.

## Tech Stack

- Node.js
- Express.js
- TypeScript
- MongoDB and Mongoose
- JWT authentication
- Stripe test-mode checkout
- Google OAuth token verification

## Getting Started

Install dependencies:

```bash
npm install
```

Create a local environment file:

```bash
cp .env.example .env
```

Run the development server:

```bash
npm run dev
```

The API runs locally on `http://localhost:5000`.

## Scripts

```bash
npm run dev
npm run build
npm start
```

## Environment Variables

Only placeholder values are committed in `.env.example`.

Required local values include:

- `MONGO_URI`
- `JWT_SECRET`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

Do not commit `.env` or any real credentials.

## Current Routes

- `GET /` - server status
- `GET /api/health` - health check
