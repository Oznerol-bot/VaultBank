require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const { Resend } = require('resend');


const app = express();
const PORT = process.env.PORT || 3000;
const resend = new Resend(process.env.RESEND_API_KEY);

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
  password: { type: String, required: true, minlength: 6},
  username: { type: String, required: true, unique: true, trim: true, lowercase: true }, 

 
  currentBalance: { type: Number, default: 500 }, 
  savingsBalance: { type: Number, default: 500 }, 
  investmentBalance: { type: Number, default: 500 }, 
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending"},
  approvedAt: { type: Date },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  rejectedAt: { type: Date }

}, { timestamps: true }); 

authSchema.pre("save", async function () { 

    if (!this.isModified("password")) return; 
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    } catch (err) {
        throw err;
    }
});

authSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};


const adminSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, required: true, enum: ["admin"], default: "admin"}
}, { timestamps: true });

adminSchema.pre("save", async function () { 

  if (!this.isModified("password")) return; 
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  } catch (err) {
    throw err;
  }
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
  relatedTransactionId: { type: String, trim: true, default: null },
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
    const { firstName, lastName, email, contactNumber, password, username } = req.body;
    if (!firstName || !lastName || !email || !contactNumber || !password || !username) {
      return res.status(400).json({ 
        message: 'All fields are required: firstName, lastName, email, contactNumber, password, username' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long' 
      });
    }

    const existingUser = await Auth.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Username';
      return res.status(400).json({ 
        message: `${field} is already registered. Please use another one.` 
      });
    }

    const user = new Auth({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase().trim(),
      contactNumber: contactNumber.trim(),
      username: username.toLowerCase().trim(),
      password
    });

    await user.save();

    return res.status(201).json({ 
      message: 'Registration successful! Please wait for admin approval.' 
    });

  } catch (err) {
    console.error('Registration error:', err); 

    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors 
      });
    }

    if (err.code === 11000) { 
      return res.status(400).json({ 
        message: 'Email or Username already exists. Please use a different one.' 
      });
    }

    res.status(500).json({ 
      message: 'Server error during registration',
      error: err.message 
    });
  } 
});

app.post('/api/v1/admin/register', async (req, res) => {  
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        message: 'All fields are required: username, email, password' 
      });
    }
    const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
    if (existingAdmin) {
      return res.status(400).json({ 
        message: 'Username or Email is already registered.' 
      });
    }

    const newAdmin = new Admin({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: password
    });

    await newAdmin.save();

    return res.status(201).json({ 
      message: 'Admin registration successful!', 
      adminId: newAdmin._id 
    });

  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ 
      message: 'Server error during admin registration',
      error: err.message 
    });
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
    const { identifier, password } = req.body;
    const user = await Auth.findOne({ 
        $or: [
            { email: identifier },
            { username: identifier }
        ]
    });

    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.status !== 'approved') return res.status(403).json({ message: 'Account not approved' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, message: 'Login successful' });

  } catch (err) {
    console.error("Login Error Details:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/api/v1/auth/logout', authMiddleware, async (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/v1/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put('/api/v1/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, email, contactNumber } = req.body;
    const updates = {};
    if (firstName) updates.firstName = firstName.trim();
    if (lastName) updates.lastName = lastName.trim();
    if (contactNumber) updates.contactNumber = contactNumber.trim();
    if (email) {
        const trimmedEmail = email.toLowerCase().trim();
        const existingUser = await Auth.findOne({ email: trimmedEmail, _id: { $ne: req.userId } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email is already taken by another account.' });
        }
        updates.email = trimmedEmail;
    }
    
    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ message: 'No valid fields provided for update.' });
    }

    const user = await Auth.findByIdAndUpdate(
        req.userId, 
        { $set: updates }, 
        { new: true, runValidators: true }
    ).select('-password');

    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ 
        message: 'Profile updated successfully', 
        user 
    });

  } catch (err) {
    console.error('Profile update error:', err);
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors 
      });
    }
    if (err.code === 11000) { 
        return res.status(400).json({ 
            message: 'A field you tried to update already exists (e.g., email or username).' 
        });
    }
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.patch('/api/v1/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }
    const user = await Auth.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) return res.status(400).json({ message: 'Invalid current password.' });
    user.password = newPassword;
    await user.save(); 
    res.json({ message: 'Password updated successfully. Please log in again with your new password.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

//++++++++ Admin Routes ++++++++

app.get('/api/v1/users', adminMiddleware, async (req, res) => {
  try {
    const users = await Auth.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get('/api/v1/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.params.userId).select('-password');
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
      .select('-password');
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

    await resend.emails.send({
      from: 'Vault Bank <no-reply@onresend.com>',  
      to: user.email,
      subject: 'Your Vault Bank Account Has Been Approved!',
      html: `
        <h2>Welcome to Vault Bank, ${user.firstName}!</h2>
        <p>Your account has been <b>approved</b> by our admin team.</p>
        <p>You can now log in and start using your banking dashboard.</p>
        <br/>
        <p>Thank you for registering with Vault Bank.</p>
      `
    });
    

    res.json({ message: "User approved successfully and email sent", user });
  } catch (err) {
    console.error("Approval Error:", err);
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

    await resend.emails.send({
      from: 'Acme <onboarding@resend.dev>',
      to: user.email,
      subject: 'Vault Bank Account Rejection',
      html: `
      <h2>Hello ${user.firstName},</h2>
      <p>Unfortunately, your account was <b>rejected</b>.</p>
      <p>Please contact support if you think this is a mistake.</p>
      `
    });

    res.json({ message: "User rejected successfully and email", user });
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

   
    user.currentBalance += amount;
    await user.save({ session });

    const transaction = new Transaction({ 
      userId: user._id, type: "deposit", amount, updatedBalance: user.currentBalance 
    });
    await transaction.save({ session });

    const transacReceipt = new Receipt({
     transactionId: transaction._id, userId: user._id, type: "deposit", amount,updatedBalance: user.currentBalance, receiptNumber: `R-${Date.now()}` 
    });
    await transacReceipt.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ 
      message: "You have deposited the amount successfully. Thank you for using Vault Bank", 
      balance: user.currentBalance, 
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

    if (user.currentBalance < amount) return res.status(400).json({ message: "Insufficient balance" });

    user.currentBalance -= amount;
    await user.save({ session });

    const transaction = new Transaction({
      userId: user._id, type: "withdraw", amount, updatedBalance: user.currentBalance 
    });
    await transaction.save({ session });

    const transacReceipt = new Receipt({
      transactionId: transaction._id, userId: user._id, type: "withdraw", amount, updatedBalance: user.currentBalance, receiptNumber: `R-${Date.now()}` 
    });
    await transacReceipt.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ 
      message: "You have successfully withdrawn an amount. Thank you for using Vault Bank", 
      balance: user.currentBalance, 
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
    
    if (sender.currentBalance < amount) return res.status(400).json({ message: "Insufficient balance" });

    sender.currentBalance -= amount;
    receiver.currentBalance += amount; // Assumption: Transfers are received into Current Balance

    await sender.save({ session });
    await receiver.save({ session });

    const transaction = new Transaction({
      userId: sender._id, type: "transfer", amount, sender: sender._id, receiver: receiver._id, updatedBalance: sender.currentBalance 
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
      senderBalance: sender.currentBalance, 
      receiverBalance: receiver.currentBalance, 
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
    const { ticketSubject, ticketDescription, relatedTransactionId } = req.body;
    if (!ticketSubject || !ticketDescription) return res.status(400).json({ message: 'There is an incomplete input. PLease add the required inputs' });

    const ticket = new Ticket({ userId: req.userId, ticketSubject, ticketDescription, relatedTransactionId: relatedTransactionId || null 
    });
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

// ++++++++ Reports Routes ++++++++

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

app.get('/api/v1/reports/transactions-summary', authMiddleware, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);
    
    const senderSummary = await Transaction.aggregate([
      { $match: { userId: userId } },
      {
        $group: {
          _id: null,
          totalDeposit: { $sum: { $cond: [{ $eq: ["$type", "deposit"] }, "$amount", 0] } },
          totalWithdraw: { $sum: { $cond: [{ $eq: ["$type", "withdraw"] }, "$amount", 0] } },
          totalTransferOut: { $sum: { $cond: [{ $eq: ["$type", "transfer"] }, "$amount", 0] } } 
        }
      }
    ]);
    
    const receiverSummary = await Transaction.aggregate([
      { $match: { receiver: userId, type: "transfer" } },
      {
        $group: {
          _id: null,
          totalTransferIn: { $sum: "$amount" }
        }
      }
    ]);

    const deposits = senderSummary[0] ? senderSummary[0].totalDeposit : 0;
    const transfersIn = receiverSummary[0] ? receiverSummary[0].totalTransferIn : 0;
    const withdrawals = senderSummary[0] ? senderSummary[0].totalWithdraw : 0;
    const transfersOut = senderSummary[0] ? senderSummary[0].totalTransferOut : 0;

    const totalIncome = deposits + transfersIn;
 
    const totalExpenses = withdrawals + transfersOut;

    const user = await Auth.findById(req.userId).select('currentBalance');
    const netBalance = user ? user.currentBalance : 0;
    
    const rawTransactions = await Transaction.find({ 
        $or: [
            { userId: userId },
            { receiver: userId, type: "transfer" } 
        ]
    })
      .select('_id type amount createdAt sender receiver')
      .sort({ createdAt: -1 });

    const formattedTransactions = rawTransactions.map(tx => {
        const isTransferOut = tx.type === 'transfer' && tx.sender && tx.sender.equals(userId);
        const isTransferIn = tx.type === 'transfer' && tx.receiver && tx.receiver.equals(userId);
        const isDeposit = tx.type === 'deposit';

        let typeLabel = tx.type.charAt(0).toUpperCase() + tx.type.slice(1);
        let isIncome = isDeposit || isTransferIn;
        
        if (isTransferOut) {
            typeLabel = "Transfer (Out)";
        } else if (isTransferIn) {
            typeLabel = "Transfer (In)";
        }
        return {
            transactionId: tx._id,
            date: tx.createdAt.toISOString().substring(0, 10),
            type: typeLabel,
            amount: tx.amount,
            isIncome: isIncome,
        };
    });

    res.json({
      summary: {
        totalIncome: totalIncome,
        totalExpenses: totalExpenses,
        netBalance: netBalance,
      },
      transactions: formattedTransactions,
    });

  } catch (err) {
    console.error('Transaction Summary Error:', err);
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

// ++++++++ Dashboard Routes ++++++++

app.get('/api/v1/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const user = await Auth.findById(req.userId).select('firstName lastName email currentBalance savingsBalance investmentBalance status');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const totalBalance = user.currentBalance + user.savingsBalance + user.investmentBalance;

    const recentTransactions = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 }) 
      .limit(5);

    const summary = await Transaction.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.userId) } },
      {
        $group: {
          _id: "$type",
          totalAmount: { $sum: "$amount" },
          count: { $sum: 1 }
        }
      }
    ]);
    

    const transactionSummary = summary.reduce((acc, item) => {
      acc[item._id] = item.totalAmount;
      return acc;
    }, { deposit: 0, withdraw: 0, transfer: 0 });


    res.json({
      message: 'Dashboard data fetched successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        totalBalance: totalBalance,
        currentBalance: user.currentBalance,
        savingsBalance: user.savingsBalance,
        investmentBalance: user.investmentBalance,
        status: user.status
      },
      recentTransactions: recentTransactions,
      transactionSummary: transactionSummary
    });

  } catch (err) {
    console.error('Dashboard summary error:', err);
    res.status(500).json({ message: 'Internal Server Error', error: err.message });
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