import cors from 'cors'
import bcrypt from 'bcryptjs'
import dotenv from 'dotenv'
import express from 'express'
import { MongoClient, ObjectId } from 'mongodb'
import multer from 'multer'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import crypto from 'node:crypto'
import dns from 'node:dns'
import nodemailer from 'nodemailer'

// MongoDB SRV DNS resolution
dns.setServers(['8.8.8.8', '1.1.1.1'])

// ---------------------------------------------------------
// BASIC SETUP
// ---------------------------------------------------------

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

dotenv.config({
  path: path.join(__dirname, '.env'),
})

// ---------------------------------------------------------
// DIRECTORIES
// ---------------------------------------------------------

const uploadDirectory = path.join(__dirname, 'uploads')

fs.mkdirSync(uploadDirectory, {
  recursive: true,
})

// ---------------------------------------------------------
// ENVIRONMENT VARIABLES
// ---------------------------------------------------------

const mongoUri = process.env.MONGODB_URI
const mongoDatabaseName =
  process.env.MONGODB_DATABASE || 'vaishnora_kraft'

const adminIdentifier =
  String(process.env.ADMIN_IDENTIFIER || '')
    .trim()
    .toLowerCase()

const adminPassword =
  process.env.ADMIN_PASSWORD || ''

const tokenSecret =
  process.env.AUTH_SECRET ||
  'vaishnora-kraft-development-secret'

// ---- EMAIL (Gmail SMTP via nodemailer) ----
const emailUser = process.env.EMAIL_USER || ''
const emailAppPassword = process.env.EMAIL_APP_PASSWORD || ''

// ---- SMS (Fast2SMS OTP route) ----
const fast2smsApiKey = process.env.FAST2SMS_API_KEY || ''

const otpExpiryMinutes =
  Number(process.env.OTP_EXPIRY_MINUTES || 5)

const otpResendCooldownSeconds =
  Number(process.env.OTP_RESEND_COOLDOWN_SECONDS || 45)

// ---------------------------------------------------------
// MONGODB
// ---------------------------------------------------------

let mongoClient

let customersCollection
let reviewsCollection
let ordersCollection
let productsCollection
let otpsCollection

const getMongoDatabase = async () => {
  if (mongoClient) {
    return mongoClient.db(mongoDatabaseName)
  }

  if (!mongoUri) {
    throw new Error('MONGODB_URI is not configured')
  }

  mongoClient = new MongoClient(mongoUri)

  await mongoClient.connect()

  console.log('MongoDB connected')

  return mongoClient.db(mongoDatabaseName)
}

// ---------------------------------------------------------
// CUSTOMERS COLLECTION
// ---------------------------------------------------------

const getCustomersCollection = async () => {
  if (customersCollection) {
    return customersCollection
  }

  customersCollection =
    (await getMongoDatabase()).collection('customers')

  await customersCollection.createIndex(
    { identifier: 1 },
    { unique: true }
  )

  return customersCollection
}

// ---------------------------------------------------------
// PRODUCTS COLLECTION
// ---------------------------------------------------------

const getProductsCollection = async () => {
  if (productsCollection) {
    return productsCollection
  }

  productsCollection =
    (await getMongoDatabase()).collection('products')

  await productsCollection.createIndex({
    category: 1,
  })

  await productsCollection.createIndex({
    bestseller: 1,
  })

  await productsCollection.createIndex({
    date: -1,
  })

  return productsCollection
}

// ---------------------------------------------------------
// REVIEWS COLLECTION
// ---------------------------------------------------------

const getReviewsCollection = async () => {
  if (reviewsCollection) {
    return reviewsCollection
  }

  reviewsCollection =
    (await getMongoDatabase()).collection('reviews')

  await reviewsCollection.createIndex({
    productId: 1,
    createdAt: -1,
  })

  return reviewsCollection
}

// ---------------------------------------------------------
// ORDERS COLLECTION
// ---------------------------------------------------------

const getOrdersCollection = async () => {
  if (ordersCollection) {
    return ordersCollection
  }

  ordersCollection =
    (await getMongoDatabase()).collection('orders')

  await ordersCollection.createIndex({
    customerId: 1,
    createdAt: -1,
  })

  return ordersCollection
}

// ---------------------------------------------------------
// OTPS COLLECTION
// ---------------------------------------------------------

const getOtpsCollection = async () => {
  if (otpsCollection) {
    return otpsCollection
  }

  otpsCollection =
    (await getMongoDatabase()).collection('otps')

  await otpsCollection.createIndex(
    { identifier: 1 },
    { unique: true }
  )

  // TTL index: Mongo will auto-delete expired OTP docs
  await otpsCollection.createIndex(
    { expiresAt: 1 },
    { expireAfterSeconds: 0 }
  )

  return otpsCollection
}

// ---------------------------------------------------------
// EXPRESS
// ---------------------------------------------------------

const app = express()

const port =
  Number(process.env.PORT || 4000)

// NOTE: no trailing slash - the browser's Origin header
// never has one, so a trailing "/" here would silently
// break CORS matching and block every request from the
// frontend.
const frontendOrigins = (
  process.env.FRONTEND_ORIGINS ||
  process.env.FRONTEND_ORIGIN ||
  'https://vaishnorakraftfrontend.vercel.app'
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

if (process.env.NODE_ENV !== 'production') {
  frontendOrigins.push(
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  )
}

// ---------------------------------------------------------
// MULTER
// ---------------------------------------------------------

const upload = multer({
  dest: uploadDirectory,

  limits: {
    fileSize: 25 * 1024 * 1024,
    files: 2,
  },

  fileFilter: (_request, file, callback) => {
    const isImage =
      file.mimetype.startsWith('image/')

    const isVideo =
      file.mimetype.startsWith('video/')

    callback(null, isImage || isVideo)
  },
})

// ---------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------

app.use(
  cors({
    origin(origin, callback) {
      // Requests without an Origin header (health checks, curl) are safe.
      // Browser requests must come from a configured frontend deployment.
      callback(null, !origin || frontendOrigins.includes(origin))
    },
    credentials: true,
  })
)

app.use(express.json())

app.use(
  '/uploads',
  express.static(uploadDirectory)
)

// ---------------------------------------------------------
// ROOT
// ---------------------------------------------------------

app.get('/', (_request, response) => {
  response.json({
    service: 'vaishnora-kraft-api',
    status: 'running',
    health: '/api/health',
    products: '/api/products',
  })
})

// ---------------------------------------------------------
// HEALTH
// ---------------------------------------------------------

app.get('/api/health', (_request, response) => {
  response.json({
    status: 'ok',
    service: 'vaishnora-kraft-backend',
    database: mongoUri
      ? 'configured'
      : 'not configured',
    email: emailUser
      ? 'configured'
      : 'not configured',
    sms: fast2smsApiKey
      ? 'configured'
      : 'not configured',
  })
})

// =========================================================
// AUTH HELPERS
// =========================================================

const normalizeIdentifier = (value) =>
  String(value || '')
    .trim()
    .toLowerCase()

const isEmailIdentifier = (identifier) =>
  identifier.includes('@')

const isValidIdentifier = (value) => {
  const identifier = normalizeIdentifier(value)

  if (!identifier) {
    return false
  }

  // Email
  if (identifier.includes('@')) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)
  }

  // Phone
  return /^[0-9+\-\s()]{7,20}$/.test(identifier)
}

// ---------------------------------------------------------
// PUBLIC CUSTOMER
// ---------------------------------------------------------

const publicCustomer = (customer) => ({
  id: String(customer._id),
  identifier: customer.identifier,
  name: customer.name || '',
  role: customer.role || 'customer',
})

// =========================================================
// OTP HELPERS
// =========================================================

const generateOtp = () => {
  return String(Math.floor(100000 + Math.random() * 900000))
}

const hashOtp = (otp) => {
  return crypto
    .createHash('sha256')
    .update(String(otp))
    .digest('hex')
}

// ---------------------------------------------------------
// EMAIL TRANSPORTER (Gmail SMTP)
// ---------------------------------------------------------

let emailTransporter

const getEmailTransporter = () => {
  if (!emailUser || !emailAppPassword) {
    throw new Error(
      'EMAIL_USER / EMAIL_APP_PASSWORD is not configured'
    )
  }

  if (!emailTransporter) {
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: emailUser,
        pass: emailAppPassword,
      },
    })
  }

  return emailTransporter
}

const sendOtpEmail = async (toEmail, otp) => {
  const transporter = getEmailTransporter()

  await transporter.sendMail({
    from: `"Vaishnora Kraft" <${emailUser}>`,
    to: toEmail,
    subject: 'Your Vaishnora Kraft OTP code',
    text: `Your OTP is ${otp}. It expires in ${otpExpiryMinutes} minutes. Do not share this code with anyone.`,
    html: `<p>Your OTP is <b>${otp}</b>.</p><p>It expires in ${otpExpiryMinutes} minutes. Do not share this code with anyone.</p>`,
  })
}

// ---------------------------------------------------------
// SMS (Fast2SMS OTP route)
// ---------------------------------------------------------

const sendOtpSms = async (phone, otp) => {
  if (!fast2smsApiKey) {
    throw new Error('FAST2SMS_API_KEY is not configured')
  }

  const digitsOnly = String(phone).replace(/\D/g, '')

  // Fast2SMS expects a bare 10-digit Indian mobile number
  const last10 = digitsOnly.slice(-10)

  const url = new URL('https://www.fast2sms.com/dev/bulkV2')

  url.searchParams.set('authorization', fast2smsApiKey)
  url.searchParams.set('route', 'otp')
  url.searchParams.set('variables_values', otp)
  url.searchParams.set('flash', '0')
  url.searchParams.set('numbers', last10)

  const response = await fetch(url, {
    method: 'GET',
  })

  const data = await response.json()

  if (!data.return) {
    throw new Error(
      data.message ? String(data.message) : 'SMS provider error'
    )
  }
}

// ---------------------------------------------------------
// TOKEN
// ---------------------------------------------------------

const encodeTokenPart = (value) =>
  Buffer.from(
    JSON.stringify(value)
  ).toString('base64url')

const createToken = (user) => {
  const payload = encodeTokenPart({
    id: user.id,
    role: user.role,
    exp:
      Date.now() +
      7 * 24 * 60 * 60 * 1000,
  })

  const signature =
    crypto
      .createHmac(
        'sha256',
        tokenSecret
      )
      .update(payload)
      .digest('base64url')

  return `${payload}.${signature}`
}

// ---------------------------------------------------------
// VERIFY TOKEN
// ---------------------------------------------------------

const verifyToken = (token) => {
  try {
    const parts = token.split('.')

    if (parts.length !== 2) {
      return null
    }

    const [payload, signature] = parts

    const expectedSignature =
      crypto
        .createHmac(
          'sha256',
          tokenSecret
        )
        .update(payload)
        .digest('base64url')

    if (signature !== expectedSignature) {
      return null
    }

    const decoded = JSON.parse(
      Buffer.from(
        payload,
        'base64url'
      ).toString('utf8')
    )

    if (!decoded.exp || decoded.exp < Date.now()) {
      return null
    }

    return decoded
  } catch {
    return null
  }
}

// ---------------------------------------------------------
// AUTHENTICATE
// ---------------------------------------------------------

const authenticate = (request, response, next) => {
  const header =
    request.headers.authorization || ''

  if (!header.startsWith('Bearer ')) {
    return response.status(401).json({
      error: 'Authentication required',
    })
  }

  const token =
    header.slice('Bearer '.length).trim()

  const user = verifyToken(token)

  if (!user) {
    return response.status(401).json({
      error: 'Invalid or expired token',
    })
  }

  request.user = user

  next()
}

// ---------------------------------------------------------
// REQUIRE CUSTOMER
// ---------------------------------------------------------

const requireCustomer = (
  request,
  response,
  next
) => {
  if (
    request.user?.role !== 'customer'
  ) {
    return response.status(403).json({
      error: 'Customer access required',
    })
  }

  next()
}

// ---------------------------------------------------------
// REQUIRE ADMIN
// ---------------------------------------------------------

const requireAdmin = (
  request,
  response,
  next
) => {
  if (
    request.user?.role !== 'admin'
  ) {
    return response.status(403).json({
      error: 'Admin access required',
    })
  }

  next()
}

// =========================================================
// AUTH ROUTES
// =========================================================

// ---------------------------------------------------------
// REGISTER
// ---------------------------------------------------------

app.post(
  '/api/auth/register',
  async (request, response, next) => {
    try {
      const {
        identifier,
        password,
        name,
      } = request.body

      const normalizedIdentifier =
        normalizeIdentifier(identifier)

      if (
        !isValidIdentifier(
          normalizedIdentifier
        )
      ) {
        return response.status(400).json({
          error:
            'Enter a valid email or phone number',
        })
      }

      if (
        !password ||
        String(password).length < 6
      ) {
        return response.status(400).json({
          error:
            'Password must be at least 6 characters',
        })
      }

      const customers =
        await getCustomersCollection()

      const existing =
        await customers.findOne({
          identifier:
            normalizedIdentifier,
        })

      if (existing) {
        return response.status(409).json({
          error:
            'An account with this identifier already exists',
        })
      }

      const passwordHash =
        await bcrypt.hash(
          String(password),
          10
        )

      const customer = {
        identifier:
          normalizedIdentifier,

        passwordHash,

        name:
          String(name || '').trim(),

        role: 'customer',

        createdAt: new Date(),
      }

      const result =
        await customers.insertOne(
          customer
        )

      const user = {
        id: String(result.insertedId),
        role: 'customer',
      }

      response.status(201).json({
        token: createToken(user),
        customer: publicCustomer({
          ...customer,
          _id: result.insertedId,
        }),
      })
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// LOGIN
// ---------------------------------------------------------

app.post(
  '/api/auth/login',
  async (request, response, next) => {
    try {
      const {
        identifier,
        password,
      } = request.body

      const normalizedIdentifier =
        normalizeIdentifier(identifier)

      // ADMIN LOGIN
      if (
        normalizedIdentifier ===
          adminIdentifier &&
        password === adminPassword
      ) {
        const admin = {
          id: 'admin',
          role: 'admin',
        }

        return response.json({
          token: createToken(admin),

          customer: {
            id: 'admin',
            identifier:
              adminIdentifier,
            name: 'Administrator',
            role: 'admin',
          },
        })
      }

      // CUSTOMER LOGIN
      const customers =
        await getCustomersCollection()

      const customer =
        await customers.findOne({
          identifier:
            normalizedIdentifier,
        })

      if (!customer || !customer.passwordHash) {
        return response.status(401).json({
          error:
            'Invalid identifier or password',
        })
      }

      const passwordMatches =
        await bcrypt.compare(
          String(password || ''),
          customer.passwordHash
        )

      if (!passwordMatches) {
        return response.status(401).json({
          error:
            'Invalid identifier or password',
        })
      }

      const user = {
        id: String(customer._id),
        role: 'customer',
      }

      response.json({
        token: createToken(user),
        customer:
          publicCustomer(customer),
      })
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// SEND OTP (email or mobile)
// ---------------------------------------------------------

app.post(
  '/api/auth/otp/send',
  async (request, response, next) => {
    try {
      const { identifier } = request.body

      const normalizedIdentifier =
        normalizeIdentifier(identifier)

      if (!isValidIdentifier(normalizedIdentifier)) {
        return response.status(400).json({
          error: 'Enter a valid email or phone number',
        })
      }

      const otps = await getOtpsCollection()

      const existing = await otps.findOne({
        identifier: normalizedIdentifier,
      })

      if (
        existing &&
        existing.lastSentAt &&
        Date.now() - existing.lastSentAt.getTime() <
          otpResendCooldownSeconds * 1000
      ) {
        const waitSeconds = Math.ceil(
          (otpResendCooldownSeconds * 1000 -
            (Date.now() - existing.lastSentAt.getTime())) /
            1000
        )

        return response.status(429).json({
          error: `Please wait ${waitSeconds}s before requesting another OTP`,
        })
      }

      const otp = generateOtp()
      const otpHash = hashOtp(otp)

      const expiresAt = new Date(
        Date.now() + otpExpiryMinutes * 60 * 1000
      )

      const channel = isEmailIdentifier(normalizedIdentifier)
        ? 'email'
        : 'mobile'

      await otps.updateOne(
        { identifier: normalizedIdentifier },
        {
          $set: {
            identifier: normalizedIdentifier,
            otpHash,
            expiresAt,
            attempts: 0,
            channel,
            lastSentAt: new Date(),
          },
        },
        { upsert: true }
      )

      if (channel === 'email') {
        await sendOtpEmail(normalizedIdentifier, otp)
      } else {
        await sendOtpSms(normalizedIdentifier, otp)
      }

      response.json({
        message: `OTP sent via ${channel}`,
        channel,
        expiresInMinutes: otpExpiryMinutes,
      })
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// VERIFY OTP (login or register, then issue token)
// ---------------------------------------------------------

app.post(
  '/api/auth/otp/verify',
  async (request, response, next) => {
    try {
      const { identifier, otp, name } = request.body

      const normalizedIdentifier =
        normalizeIdentifier(identifier)

      if (!isValidIdentifier(normalizedIdentifier)) {
        return response.status(400).json({
          error: 'Enter a valid email or phone number',
        })
      }

      const submittedOtp = String(otp || '').trim()

      if (!/^\d{6}$/.test(submittedOtp)) {
        return response.status(400).json({
          error: 'Enter the 6 digit OTP',
        })
      }

      const otps = await getOtpsCollection()

      const otpRecord = await otps.findOne({
        identifier: normalizedIdentifier,
      })

      if (!otpRecord) {
        return response.status(400).json({
          error: 'No OTP was requested for this identifier',
        })
      }

      if (otpRecord.expiresAt.getTime() < Date.now()) {
        await otps.deleteOne({ identifier: normalizedIdentifier })

        return response.status(400).json({
          error: 'OTP has expired, please request a new one',
        })
      }

      if (otpRecord.attempts >= 5) {
        await otps.deleteOne({ identifier: normalizedIdentifier })

        return response.status(429).json({
          error: 'Too many incorrect attempts, please request a new OTP',
        })
      }

      if (hashOtp(submittedOtp) !== otpRecord.otpHash) {
        await otps.updateOne(
          { identifier: normalizedIdentifier },
          { $inc: { attempts: 1 } }
        )

        return response.status(400).json({
          error: 'Incorrect OTP',
        })
      }

      // OTP correct - consume it
      await otps.deleteOne({ identifier: normalizedIdentifier })

      const customers = await getCustomersCollection()

      let customer = await customers.findOne({
        identifier: normalizedIdentifier,
      })

      if (!customer) {
        const newCustomer = {
          identifier: normalizedIdentifier,
          passwordHash: null,
          name: String(name || '').trim(),
          role: 'customer',
          createdAt: new Date(),
        }

        const result = await customers.insertOne(newCustomer)

        customer = {
          ...newCustomer,
          _id: result.insertedId,
        }
      }

      const user = {
        id: String(customer._id),
        role: 'customer',
      }

      response.json({
        token: createToken(user),
        customer: publicCustomer(customer),
      })
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// CURRENT USER
// ---------------------------------------------------------

app.get(
  '/api/auth/me',
  authenticate,
  async (request, response, next) => {
    try {
      if (
        request.user.role === 'admin'
      ) {
        return response.json({
          customer: {
            id: 'admin',
            identifier:
              adminIdentifier,
            name: 'Administrator',
            role: 'admin',
          },
        })
      }

      const customers =
        await getCustomersCollection()

      const customer =
        await customers.findOne({
          _id: new ObjectId(
            request.user.id
          ),
        })

      if (!customer) {
        return response.status(404).json({
          error: 'Customer not found',
        })
      }

      response.json({
        customer:
          publicCustomer(customer),
      })
    } catch (error) {
      next(error)
    }
  }
)

// =========================================================
// PRODUCT HELPERS
// =========================================================

const validateProduct = (body) => {
  const required = [
    'name',
    'description',
    'category',
    'subCategory',
  ]

  const missing =
    required.find(
      (field) =>
        !String(
          body[field] || ''
        ).trim()
    )

  if (missing) {
    return `${missing} is required`
  }

  if (
    !Number.isFinite(
      Number(body.price)
    ) ||
    Number(body.price) < 0
  ) {
    return 'price must be a positive number'
  }

  return null
}

// ---------------------------------------------------------
// CONVERT MONGODB PRODUCT FOR FRONTEND
// ---------------------------------------------------------

const serializeProduct = (product) => ({
  ...product,

  _id: String(product._id),
})

// =========================================================
// PRODUCT ROUTES
// =========================================================

// ---------------------------------------------------------
// GET ALL PRODUCTS
// ---------------------------------------------------------

app.get(
  '/api/products',
  async (request, response, next) => {
    try {
      const {
        category,
        bestseller,
      } = request.query

      const products =
        await getProductsCollection()

      const filter = {}

      if (category) {
        filter.category = category
      }

      if (bestseller === 'true') {
        filter.bestseller = true
      }

      const rows =
        await products
          .find(filter)
          .sort({
            date: -1,
          })
          .toArray()

      response.json(
        rows.map(serializeProduct)
      )
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// GET SINGLE PRODUCT
// ---------------------------------------------------------

app.get(
  '/api/products/:id',
  async (request, response, next) => {
    try {
      const { id } = request.params

      if (!ObjectId.isValid(id)) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      const products =
        await getProductsCollection()

      const product =
        await products.findOne({
          _id: new ObjectId(id),
        })

      if (!product) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      response.json(
        serializeProduct(product)
      )
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// ADD PRODUCT
// ---------------------------------------------------------

app.post(
  '/api/products',
  authenticate,
  requireAdmin,

  upload.fields([
    {
      name: 'image',
      maxCount: 1,
    },
    {
      name: 'video',
      maxCount: 1,
    },
  ]),

  async (request, response, next) => {
    try {
      const error =
        validateProduct(request.body)

      if (error) {
        return response.status(400).json({
          error,
        })
      }

      if (
        !request.files?.image?.[0]
      ) {
        return response.status(400).json({
          error:
            'Product image is required',
        })
      }

      const imageFile =
        request.files.image[0]

      const videoFile =
        request.files.video?.[0]

      const product = {
        name:
          request.body.name.trim(),

        description:
          request.body.description.trim(),

        price:
          Number(request.body.price),

        category:
          request.body.category.trim(),

        subCategory:
          request.body.subCategory.trim(),

        sizes:
          String(
            request.body.sizes ||
              'One size'
          )
            .split(',')
            .map((size) =>
              size.trim()
            )
            .filter(Boolean),

        image: [
          `/uploads/${imageFile.filename}`,
        ],

        video: videoFile
          ? [
              `/uploads/${videoFile.filename}`,
            ]
          : [],

        bestseller:
          request.body.bestseller ===
          'true',

        date: Date.now(),

        createdAt: new Date(),

        updatedAt: new Date(),
      }

      const products =
        await getProductsCollection()

      const result =
        await products.insertOne(
          product
        )

      const savedProduct = {
        ...product,

        _id: result.insertedId,
      }

      response.status(201).json(
        serializeProduct(
          savedProduct
        )
      )
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// UPDATE PRODUCT
// ---------------------------------------------------------

app.put(
  '/api/products/:id',
  authenticate,
  requireAdmin,

  upload.fields([
    {
      name: 'image',
      maxCount: 1,
    },
    {
      name: 'video',
      maxCount: 1,
    },
  ]),

  async (request, response, next) => {
    try {
      const { id } = request.params

      if (!ObjectId.isValid(id)) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      const error =
        validateProduct(request.body)

      if (error) {
        return response.status(400).json({
          error,
        })
      }

      const products =
        await getProductsCollection()

      const objectId =
        new ObjectId(id)

      const current =
        await products.findOne({
          _id: objectId,
        })

      if (!current) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      const imageFile =
        request.files?.image?.[0]

      const videoFile =
        request.files?.video?.[0]

      const updatedProduct = {
        name:
          request.body.name.trim(),

        description:
          request.body.description.trim(),

        price:
          Number(request.body.price),

        category:
          request.body.category.trim(),

        subCategory:
          request.body.subCategory.trim(),

        sizes:
          String(
            request.body.sizes ||
              'One size'
          )
            .split(',')
            .map((size) =>
              size.trim()
            )
            .filter(Boolean),

        image: imageFile
          ? [
              `/uploads/${imageFile.filename}`,
            ]
          : current.image || [],

        video: videoFile
          ? [
              `/uploads/${videoFile.filename}`,
            ]
          : current.video || [],

        bestseller:
          request.body.bestseller ===
          'true',

        updatedAt: new Date(),
      }

      await products.updateOne(
        {
          _id: objectId,
        },
        {
          $set: updatedProduct,
        }
      )

      const savedProduct =
        await products.findOne({
          _id: objectId,
        })

      response.json(
        serializeProduct(
          savedProduct
        )
      )
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// DELETE PRODUCT
// ---------------------------------------------------------

app.delete(
  '/api/products/:id',
  authenticate,
  requireAdmin,

  async (request, response, next) => {
    try {
      const { id } = request.params

      if (!ObjectId.isValid(id)) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      const products =
        await getProductsCollection()

      const result =
        await products.deleteOne({
          _id: new ObjectId(id),
        })

      if (
        result.deletedCount === 0
      ) {
        return response.status(404).json({
          error: 'Product not found',
        })
      }

      // IMPORTANT:
      // 204 means NO JSON response.
      response.status(204).send()
    } catch (error) {
      next(error)
    }
  }
)

// =========================================================
// REVIEW ROUTES
// =========================================================

// ---------------------------------------------------------
// GET PRODUCT REVIEWS
// ---------------------------------------------------------

app.get(
  '/api/products/:id/reviews',
  async (request, response, next) => {
    try {
      const productId =
        request.params.id

      const reviews =
        await getReviewsCollection()

      const rows =
        await reviews
          .find({
            productId,
          })
          .sort({
            createdAt: -1,
          })
          .toArray()

      response.json(
        rows.map((review) => ({
          ...review,
          _id: String(review._id),
        }))
      )
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// ADD REVIEW
// ---------------------------------------------------------

app.post(
  '/api/products/:id/reviews',
  authenticate,
  requireCustomer,

  async (request, response, next) => {
    try {
      const productId =
        request.params.id

      const {
        rating,
        comment,
      } = request.body

      const numericRating =
        Number(rating)

      if (
        !Number.isInteger(
          numericRating
        ) ||
        numericRating < 1 ||
        numericRating > 5
      ) {
        return response.status(400).json({
          error:
            'Rating must be between 1 and 5',
        })
      }

      if (
        !String(
          comment || ''
        ).trim()
      ) {
        return response.status(400).json({
          error:
            'Review comment is required',
        })
      }

      const products =
        await getProductsCollection()

      if (
        ObjectId.isValid(productId)
      ) {
        const product =
          await products.findOne({
            _id:
              new ObjectId(productId),
          })

        if (!product) {
          return response.status(404).json({
            error:
              'Product not found',
          })
        }
      }

      const customers =
        await getCustomersCollection()

      const customer =
        await customers.findOne({
          _id:
            new ObjectId(
              request.user.id
            ),
        })

      const reviews =
        await getReviewsCollection()

      const review = {
        productId,

        customerId:
          request.user.id,

        customerName:
          customer?.name ||
          customer?.identifier ||
          'Customer',

        rating:
          numericRating,

        comment:
          String(comment).trim(),

        createdAt:
          new Date(),
      }

      const result =
        await reviews.insertOne(
          review
        )

      response.status(201).json({
        ...review,
        _id: String(
          result.insertedId
        ),
      })
    } catch (error) {
      next(error)
    }
  }
)

// =========================================================
// ORDER ROUTES
// =========================================================

// ---------------------------------------------------------
// CREATE ORDER
// ---------------------------------------------------------

app.post(
  '/api/orders',
  authenticate,
  requireCustomer,

  async (request, response, next) => {
    try {
      const {
        items,
        address,
      } = request.body

      if (
        !Array.isArray(items) ||
        items.length === 0
      ) {
        return response.status(400).json({
          error:
            'Order must contain at least one item',
        })
      }

      const products =
        await getProductsCollection()

      const orderItems = []

      let subtotal = 0

      for (const item of items) {
        const productId =
          String(
            item.productId || ''
          )

        const quantity =
          Number(item.quantity)

        if (
          !ObjectId.isValid(
            productId
          )
        ) {
          return response.status(400).json({
            error:
              'Invalid product ID',
          })
        }

        if (
          !Number.isInteger(
            quantity
          ) ||
          quantity < 1 ||
          quantity > 20
        ) {
          return response.status(400).json({
            error:
              'Quantity must be between 1 and 20',
          })
        }

        const product =
          await products.findOne({
            _id:
              new ObjectId(
                productId
              ),
          })

        if (!product) {
          return response.status(404).json({
            error:
              `Product ${productId} not found`,
          })
        }

        const itemPrice =
          Number(product.price)

        const itemTotal =
          itemPrice * quantity

        subtotal += itemTotal

        orderItems.push({
          productId:
            String(product._id),

          name:
            product.name,

          price:
            itemPrice,

          quantity,

          image:
            product.image?.[0] || '',

          total:
            itemTotal,
        })
      }

      // ---------------------------------------------------
      // SHIPPING
      // ---------------------------------------------------

      const shipping =
        subtotal >= 75
          ? 0
          : 8

      const total =
        subtotal + shipping

      // ---------------------------------------------------
      // ADDRESS
      // ---------------------------------------------------

      const safeAddress =
        address &&
        typeof address === 'object'
          ? {
              firstName:
                String(
                  address.firstName ||
                    ''
                ).trim(),

              lastName:
                String(
                  address.lastName ||
                    ''
                ).trim(),

              email:
                String(
                  address.email ||
                    ''
                ).trim(),

              address:
                String(
                  address.address ||
                    ''
                ).trim(),

              city:
                String(
                  address.city ||
                    ''
                ).trim(),

              state:
                String(
                  address.state ||
                    ''
                ).trim(),

              pinCode:
                String(
                  address.pinCode ||
                    ''
                ).trim(),
            }
          : {}

      // ---------------------------------------------------
      // ORDER
      // ---------------------------------------------------

      const order = {
        customerId:
          request.user.id,

        items:
          orderItems,

        subtotal,

        shipping,

        total,

        address:
          safeAddress,

        status:
          'placed',

        createdAt:
          new Date(),

        updatedAt:
          new Date(),
      }

      const orders =
        await getOrdersCollection()

      const result =
        await orders.insertOne(
          order
        )

      response.status(201).json({
        order: {
          ...order,
          _id: String(
            result.insertedId
          ),
        },
      })
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// CUSTOMER ORDERS
// ---------------------------------------------------------

app.get(
  '/api/orders',
  authenticate,
  requireCustomer,

  async (request, response, next) => {
    try {
      const orders =
        await getOrdersCollection()

      const rows =
        await orders
          .find({
            customerId:
              request.user.id,
          })
          .sort({
            createdAt: -1,
          })
          .toArray()

      response.json(
        rows.map((order) => ({
          ...order,
          _id: String(order._id),
        }))
      )
    } catch (error) {
      next(error)
    }
  }
)

// =========================================================
// ADMIN ORDER ROUTES
// =========================================================

// ---------------------------------------------------------
// GET ALL ORDERS - ADMIN
// ---------------------------------------------------------

app.get(
  '/api/admin/orders',
  authenticate,
  requireAdmin,

  async (_request, response, next) => {
    try {
      const orders =
        await getOrdersCollection()

      const customers =
        await getCustomersCollection()

      const rows =
        await orders
          .find({})
          .sort({
            createdAt: -1,
          })
          .toArray()

      const result = []

      for (const order of rows) {
        let customer = null

        if (
          ObjectId.isValid(
            order.customerId
          )
        ) {
          customer =
            await customers.findOne({
              _id:
                new ObjectId(
                  order.customerId
                ),
            })
        }

        result.push({
          ...order,

          _id:
            String(order._id),

          customer:
            customer
              ? publicCustomer(
                  customer
                )
              : null,
        })
      }

      response.json(result)
    } catch (error) {
      next(error)
    }
  }
)

// ---------------------------------------------------------
// UPDATE ORDER STATUS
// ---------------------------------------------------------

app.patch(
  '/api/admin/orders/:id/status',
  authenticate,
  requireAdmin,

  async (request, response, next) => {
    try {
      const { id } =
        request.params

      const { status } =
        request.body

      const allowedStatuses = [
        'placed',
        'confirmed',
        'processing',
        'shipped',
        'delivered',
        'cancelled',
      ]

      if (
        !allowedStatuses.includes(
          status
        )
      ) {
        return response.status(400).json({
          error:
            'Invalid order status',
        })
      }

      if (
        !ObjectId.isValid(id)
      ) {
        return response.status(404).json({
          error:
            'Order not found',
        })
      }

      const orders =
        await getOrdersCollection()

      const result =
        await orders.findOneAndUpdate(
          {
            _id:
              new ObjectId(id),
          },
          {
            $set: {
              status,
              updatedAt:
                new Date(),
            },
          },
          {
            returnDocument: 'after',
          }
        )

      if (!result) {
        return response.status(404).json({
          error:
            'Order not found',
        })
      }

      response.json({
        order: {
          ...result,
          _id: String(
            result._id
          ),
        },
      })
    } catch (error) {
      next(error)
    }
  }
)

// =========================================================
// ERROR HANDLER
// =========================================================

app.use(
  (
    error,
    _request,
    response,
    _next
  ) => {
    console.error(error)

    if (
      error instanceof
        multer.MulterError ||
      error.message ===
        'Unexpected field'
    ) {
      return response.status(400).json({
        error:
          'Invalid image or video upload',
      })
    }

    response.status(500).json({
      error:
        'Internal server error',
    })
  }
)

// =========================================================
// START SERVER
// =========================================================

app.listen(
  port,
  () => {
    console.log(
      `Vaishnora Kraft API running at http://localhost:${port}`
    )
  }
)
