
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');


const app = express();
const PORT = process.env.PORT || 3000;

// ====== Middleware ======
app.use(cors());
app.use(express.json());

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

async function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;

    const admin = await Admin.findById(req.userId);
    if (!admin) return res.status(403).json({ message: "Not authorized" });
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}


// ====== Mongoose Schema & Model ======

const authSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  contactNumber: { type: String, required: true },
  password: { type: String, required: true,minlength: 6},

  balance: { type: Number, default: 0 },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending"},
  approvedAt: { type: Date },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  rejectedAt: { type: Date },

  twoFACode: { type: String },
  twoFAExpires: { type: Date }

}, { timestamps: true });

authSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

authSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};


const adminSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, required: true, enum: ["admin"]}
}, { timestamps: true });

adminSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Auth", required: true },
  type: { type: String, enum: ["deposit", "withdraw", "transfer"], required: true },
  amount: { type: Number, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "Auth" },   
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "Auth" }, 
  updatedBalance: { type: Number, required: true }         
}, { timestamps: true });

const receiptSchema = new mongoose.Schema({
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: "Transaction", required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Auth", required: true },
  type: { type: String, enum: ["deposit", "withdraw", "transfer"], required: true },
  amount: { type: Number, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "Auth" },   
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "Auth" }, 
  updatedBalance: { type: Number, required: true },
  receiptNumber: { type: String, required: true, unique: true },
  pdfPath: { type: String }, 
}, { timestamps: true });

const ticketSchema = new mongoose.Schema({
  userId: {type: mongoose.Schema.Types.ObjectId, ref: "Auth", required: true },
  ticketSubject: {type: String, required: true},
  ticketDescription: {type: String, required: true},
  status: {type: String, enum: ["Open", "In_progress", "Resolved", "Closed"], default: "Open"}
}, { timestamps: true });

const replySchema = new mongoose.Schema({
  ticketId: {type: mongoose.Schema.Types.ObjectId, ref: "Ticket", required: true},
  userId: {type: mongoose.Schema.Types.ObjectId, ref: "Auth", required: true },
  message: { type: String, required: true}
}, { timestamps: true });


const Reply = mongoose.model('Reply', replySchema);
const Ticket = mongoose.model('Ticket', ticketSchema);
const Receipt = mongoose.model('Receipt', receiptSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Auth = mongoose.model('Auth', authSchema);

// ====== Routes ======

app.get('/', (req, res) => {
  res.send('VaultBank API is running >_<');
});

// ++++++++ Auth Routes ++++++++

app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, contactNumber, password } = req.body;

    const existingUser = await Auth.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email is used already. Use another email for registration' });

    const user = new Auth({ firstName, lastName, email, contactNumber, password });
    await user.save();

    res.status(201).json({ message: 'You have been successfully registered, please wait for the admin approval' });
  } catch (err) {
    res.status(400).json({ message: 'There was an error in registration' });
  } 
});

app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: admin._id, role: "admin" }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, message: "Logged in successfully" });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Auth.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.status !== 'approved') return res.status(403).json({ message: 'Account not approved' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });


    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.twoFACode = code;
    user.twoFAExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiration
    await user.save();


    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Your 2FA Code.',
      text: `Your 2FA code is: ${code} . Do not reply to this message as it is an automated response`
    });

    res.json({ message: '2FA code sent to email' });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/auth/verify-2fa', async (req, res) => {
  try {
    const { email, code } = req.body;

    const user = await Auth.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.twoFACode || user.twoFAExpires < new Date()) {
      return res.status(400).json({ message: '2FA code expired, please login again' });
    }

    if (user.twoFACode !== code) return res.status(400).json({ message: 'Invalid 2FA code' });


    user.twoFACode = null;
    user.twoFAExpires = null;
    await user.save();


    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/auth/logout', authMiddleware, async (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v1/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.userId).select('-password -twoFACode -twoFAExpires');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

//++++++++ Admin Routes ++++++++

app.get('/api/v1/users', adminMiddleware, async (req, res) => {
  try {
    const users = await Auth.find().select('-password -twoFACode -twoFAExpires').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/v1/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.params.userId).select('-password -twoFACode -twoFAExpires');
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/v1/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const updates = req.body;
    const user = await Auth.findByIdAndUpdate(req.params.userId, updates, { new: true })
      .select('-password -twoFACode -twoFAExpires');
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.patch('/api/v1/users/:userId/approve', adminMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.status !== "pending") return res.status(400).json({ message: "User is not pending approval" });

    user.status = "approved";
    user.approvedAt = new Date();
    user.approvedBy = req.userId;
    await user.save();

    res.json({ message: "User approved successfully", user });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.patch('/api/v1/users/:userId/reject', adminMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.status !== "pending") return res.status(400).json({ message: "User is not pending approval" });

    user.status = "rejected";
    user.rejectedAt = new Date();
    await user.save();

    res.json({ message: "User rejected successfully", user });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

//++++++++ Transaction Routes ++++++++

app.post('/api/v1/transactions/deposit', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Amount must be positive" });

    const user = await Auth.findById(req.userId).session(session);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.balance += amount;
    await user.save({ session });

    const transaction = new Transaction({ 
      userId: user._id, type: "deposit", amount, updatedBalance: user.balance 
    });
    await transaction.save({ session });

    const transacReceipt = new Receipt({
     transactionId: transaction._id, userId: user._id, type: "deposit", amount,updatedBalance: user.balance, receiptNumber: `R-${Date.now()}`
    });
    await transacReceipt.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ 
      message: "You have deposited the amount successfully. Thank you for using Vault Bank", 
      balance: user.balance, 
      transaction 
    });   

  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/transactions/withdraw', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid. Please input a valid amount" });

    const user = await Auth.findById(req.userId).session(session);
    if (!user) return res.status(404).json({ message: "User not registered within the system" });
    if (user.balance < amount) return res.status(400).json({ message: "Insufficient balance" });

    user.balance -= amount;
    await user.save({ session });

    const transaction = new Transaction({
      userId: user._id, type: "withdraw", amount, updatedBalance: user.balance
    });
    await transaction.save({ session });

    const transacReceipt = new Receipt({
      transactionId: transaction._id, userId: user._id, type: "withdraw", amount, updatedBalance: user.balance, receiptNumber: `R-${Date.now()}`
    });
    await transacReceipt.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ 
      message: "You have successfully withdrawn an amount. Thank you for using Vault Bank", 
      balance: user.balance, 
      transaction 
    });

  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/transactions/transfer', authMiddleware, async (req, res) => {
 const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { toEmail, amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid. Please input a valid amount" });

    const sender = await Auth.findById(req.userId).session(session);
    const receiver = await Auth.findOne({ email: toEmail }).session(session);

    if (!sender || !receiver) return res.status(404).json({ message: "User(s) not registered within the system" });
    if (sender.balance < amount) return res.status(400).json({ message: "Insufficient balance" });

    sender.balance -= amount;
    receiver.balance += amount;

    await sender.save({ session });
    await receiver.save({ session });

    const transaction = new Transaction({
      userId: sender._id, type: "transfer", amount, sender: sender._id, receiver: receiver._id, updatedBalance: sender.balance
    });
    await transaction.save({ session });

    const transacReceipt = new Receipt({
      transactionId: transaction._id, userId: sender._id, type: transaction.type, amount: transaction.amount, sender: transaction.sender,
      receiver: transaction.receiver,  updatedBalance: transaction.updatedBalance, receiptNumber: `R-${Date.now()}`, pdfPath: null
    });
    await transacReceipt.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({
      message: "Transfer is successful! Thank you for using Vault Bank",
      senderBalance: sender.balance,
      receiverBalance: receiver.balance,
      transaction
    });

  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// ++++++++ Transaction Receipt Routes ++++++++

app.get('/api/v1/transactions/:transactionId/receipt', authMiddleware, async (req, res) => {
  try {
    const { transactionId } = req.params;
    
    const receipt = await Receipt.findOne({ transactionId });
    if (!receipt) return res.status(404).json({ message: "Transaction is not found. Cannot see any receipts" });

    res.json(receipt);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/v1/receipts/:receiptId/download', authMiddleware, async (req, res) => {
  try {
    const { receiptId } = req.params;

    const receipt = await Receipt.findById(receiptId)
    .populate('sender', 'firstName lastName email')
    .populate('receiver', 'firstName lastName email');
    if (!receipt) return res.status(404).json({ message: "Receipt not found" });

    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=receipt-${receipt.receiptNumber}.pdf`);

    doc.pipe(res);
    doc.fontSize(20).text('Vault Bank Receipt', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Receipt Number: ${receipt.receiptNumber}`);
    doc.text(`Transaction ID: ${receipt.transactionId}`);
    doc.text(`Type: ${receipt.type}`);
    doc.text(`Amount: ${receipt.amount}`);
    if (receipt.sender) doc.text(`Sender: ${receipt.sender.firstName} ${receipt.sender.lastName} (${receipt.sender.email})`);
    if (receipt.receiver) doc.text(`Receiver: ${receipt.receiver.firstName} ${receipt.receiver.lastName} (${receipt.receiver.email})`);
    doc.text(`Updated Balance: ${receipt.updatedBalance}`);
    doc.text(`Date: ${receipt.createdAt}`);

    doc.end();
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ++++++++ Support Ticket Routes ++++++++

app.get('/api/v1/tickets', authMiddleware, async (req, res) => {
  try {
    let tickets;
    const admin = await Admin.findById(req.userId);

    if (admin) {
      tickets = await Ticket.find().populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
    } else {
      tickets = await Ticket.find({ userId: req.userId }).populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
    }

    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/tickets', authMiddleware, async (req, res) => {
  try {
    const { ticketSubject, ticketDescription } = req.body;
    if (!ticketSubject || !ticketDescription) return res.status(400).json({ message: 'There is an incomplete input. PLease add the required inputs' });

    const ticket = new Ticket({ userId: req.userId, ticketSubject, ticketDescription });
    await ticket.save();

    res.status(201).json({ message: 'Support Ticket submitted successfully. PLease wait for an admin to resolve the issue', ticket });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/v1/tickets/:ticketId', authMiddleware, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.ticketId).populate('userId', 'firstName lastName email');
    if (!ticket) return res.status(404).json({ message: 'Support Ticket not found within the system' });

    const admin = await Admin.findById(req.userId);
    if (!admin && ticket.userId._id.toString() !== req.userId) {
      return res.status(403).json({ message: 'You are not authorized to view this ticket' });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error"});
  }
});

app.patch('/api/v1/tickets/:ticketId/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["Open", "In_progress", "Resolved", "Closed"].includes(status)) {
      return res.status(400).json({ message: 'Invalid status value. Please choose a valid status' });
    }

    const ticket = await Ticket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Support Ticket not found within the system' });

    const admin = await Admin.findById(req.userId);
    if (!admin && ticket.userId.toString() !== req.userId) {
      return res.status(403).json({ message: 'Not authorized to update this ticket' });
    }

    ticket.status = status;
    await ticket.save();

    res.json({ message: 'Support Ticket status updated', ticket });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/tickets/:ticketId/replies', authMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'There is no input. Message is required' });

    const ticket = await Ticket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Support Ticket not found within the system' });

    const admin = await Admin.findById(req.userId);
    if (!admin && ticket.userId.toString() !== req.userId) {
      return res.status(403).json({ message: 'Not authorized to reply to this ticket' });
    }

    const reply = new Reply({ ticketId: ticket._id, userId: req.userId, message });
    await reply.save();

    res.status(201).json({ message: 'Reply sent Successfully', reply });
  } catch (err) {
    res.status(500).json({ message : "Internal Server Error" });
  }
});

app.get('/api/v1/tickets/:ticketId/replies', authMiddleware, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Support Ticket not found within the system' });

    const admin = await Admin.findById(req.userId);
    if (!admin && ticket.userId.toString() !== req.userId) {
      return res.status(403).json({ message: 'You are not authorized to view replies' });
    }

    const replies = await Reply.find({ ticketId: ticket._id }).populate('userId', 'firstName lastName email').sort({ createdAt: 1 });

    res.json(replies);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// ++++++++ REPORTS ++++++++

app.get('/api/v1/reports/transactions', authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate, type } = req.query;

    const filter = { userId: req.userId };

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    if (type) filter.type = type;

    const transactions = await Transaction.find(filter).sort({ createdAt: -1 });

    res.json({ count: transactions.length, transactions });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});


app.get('/api/v1/reports/daily-summary', authMiddleware, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: "Date is required" });

    const start = new Date(date);
    const end = new Date(date);
    end.setDate(end.getDate() + 1);

    const summary = await Transaction.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(req.userId),
          createdAt: { $gte: start, $lt: end }
        }
      },
      {

        $group: {
          _id: "$type",
          totalAmount: { $sum: "$amount" },
          count: { $sum: 1 }
        }
      }
    ]);

    res.json(summary);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});



app.get('/api/v1/reports/export', authMiddleware, async (req, res) => {
  try {
    const { format, startDate, endDate } = req.query;

    if (!format || !["pdf", "excel"].includes(format.toLowerCase())) {
      return res.status(400).json({ message: "Invalid format. Use pdf or excel" });
    }

    const filter = { userId: req.userId };

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    const transactions = await Transaction.find(filter).sort({ createdAt: -1 });


    if (format.toLowerCase() === "pdf") {
      const doc = new PDFDocument();
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=transactions-report.pdf`);
      doc.pipe(res);

      doc.fontSize(20).text('Vault Bank - Transaction Report', { align: 'center' });
      doc.moveDown();

      transactions.forEach(tx => {
        doc.fontSize(12).text(`Type: ${tx.type}`);
        doc.text(`Amount: ${tx.amount}`);
        doc.text(`Date: ${tx.createdAt}`);
        doc.text(`Updated Balance: ${tx.updatedBalance}`);
        doc.moveDown();
      });

      doc.end();
      return;
    }


    if (format.toLowerCase() === "excel") {
      let csv = "Type,Amount,Date,Updated Balance\n";
      transactions.forEach(tx => {
        csv += `${tx.type},${tx.amount},${tx.createdAt},${tx.updatedBalance}\n`;
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=transactions-report.csv');
      return res.send(csv);
    }

  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// ===== START SERVER =====
async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB Atglas');
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (err) {
    console.error('❌ Failed to connect:', err.message);
  }
}

startServer();