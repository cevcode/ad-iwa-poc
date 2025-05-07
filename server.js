require('dotenv').config()
const express = require('express')
const cors = require('cors')
const body = require('body-parser')
const passport = require('passport')
const { BearerStrategy } = require('passport-azure-ad')

const { TENANT_ID, API_APP_ID } = process.env
if (!TENANT_ID || !API_APP_ID) {
  console.error('TENANT_ID or API_APP_ID missing in .env')
  process.exit(1)
}

passport.use(
  new BearerStrategy(
    {
      identityMetadata: `https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration`,
      clientID: API_APP_ID,
      validateIssuer: true,
      allowMultiAudiencesInToken: true,
      loggingLevel: 'warn'
    },
    (token, done) => done(null, token)
  )
)

function bearerAuth(req, res, next) {
  passport.authenticate('oauth-bearer', { session: false, failWithError: true }, (err, user, info) => {
    if (err) {
      console.warn('[Auth] error:', err.message)
      return next(err)
    }
    if (!user) {
      console.warn('[Auth] failed:', info?.message || 'no info')
      return res.status(401).send(info?.message || 'Unauthorized')
    }
    const id = user.preferred_username || user.upn || user.sub
    console.log('[Auth] OK for', id)
    req.user = user
    next()
  })(req, res, next)
}

/* ——— API ——— */
const app = express()
app.use(cors({ origin: 'http://127.0.0.1:5173', credentials: true }))
app.use(body.json())

app.get('/api/user', bearerAuth, (req, res) => {
  const id = req.user.preferred_username || req.user.upn || req.user.sub
  console.log('[API] /api/user → 200 for', id)
  res.json({ user: id })
})

/* ——— start ——— */
app.listen(3001, () => console.log(`API listening on http://127.0.0.1:3001 (${process.platform})`))
