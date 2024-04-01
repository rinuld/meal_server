const express = require('express');
const cors = require('cors');
const app = express();
const mysql = require('mysql');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const csv = require('csv-parser');
const fs = require('fs');
const multer = require('multer');
// const { log } = require('console');
// const json2csv = require('json2csv').parse;
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const path = require('path');

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "nyli_meal",
});

app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000"],
  methods: ["GET", "POST", "PUT"],
  credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  key: "userid",
  secret: "secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    expires: 1000 * 60 * 60 * 24,
  },
}));

// Multer configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads'); // Directory to save the uploaded files
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage: storage });

// login
app.post(
  '/api/login',
  [
    // Validate input fields
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, recaptchaValue } = req.body;

    try {
      const verificationURL = "https://www.google.com/recaptcha/api/siteverify";
      const secretKey = "6LcrxOImAAAAAI0tc4q09dOQQMYsx0pwny3pPbrY";

      const response = await axios.post(verificationURL, null, {
        params: {
          secret: secretKey,
          response: recaptchaValue,
        },
      });

      const { success } = response.data;

      if (success) {
        // Query the user table to validate the credentials
        const query = 'SELECT * FROM users WHERE firstname = ?';
        db.query(query, [username], async (error, results) => {
          if (error) {
            console.error('Error executing SQL query', error);
            return res.status(500).json({ error: 'Internal server error' });
          }

          if (results.length > 0) {
            const user = results[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
              // Generate JWT token
              const token = jwt.sign({ userId: user.id }, 'secret', { expiresIn: '1d' });
              req.session.usersession = user;
              return res.status(200).json({ token: token, user, recaptcha: recaptchaValue });
            } else {
              // Invalid password
              console.log("not logged in");
              return res.status(401).json({ error: 'Invalid credentials' });
            }
          } else {
            // Invalid username
            return res.status(401).json({ error: 'Invalid credentials' });
          }
        });
      } else {
        // reCAPTCHA verification failed
        return res.status(400).json({ error: "reCAPTCHA verification failed" });
      }
    } catch (error) {
      // Error during reCAPTCHA verification
      console.error("Error during reCAPTCHA verification", error);
      return res.status(500).json({ error: "Error during reCAPTCHA verification" });
    }
  }
);

app.get('/api/verifyToken', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // Verify the token
  jwt.verify(token, 'your-secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Token is valid
    res.status(200).json({ message: 'Token is valid' });
  });
});

app.get('/api/session', (req, res) => {
  const user = req.session.usersession;
  if (user) {
    console.log(user);
    res.send({ loggedIn: true, user: user });
  } else {
    res.send({ loggedIn: false, user: user });
  }
})

// Create

// Set up multer storage for image upload
const storeToUpload = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Specify the destination folder for image uploads
  },
  filename: (req, file, cb) => {
    console.log(file);
    const fileName = `${Date.now()}-${file.originalname}`;
    cb(null, fileName); // Generate a unique filename for the uploaded image
  },
});

// Configure multer to only accept image files
const fileFilter = (req, file, cb) => {
  const fileTypes = /jpeg|jpg|png|gif/; // Regular expression for allowed image file formats
  const extName = fileTypes.test(path.extname(file.originalname).toLowerCase());
  const mimeType = fileTypes.test(file.mimetype);
  if (extName && mimeType) {
    cb(null, true);
  } else {
    cb('Error: Only image files are allowed!');
  }
};

// Initialize multer with the configured storage and file filter
const updateImage = multer({ storage: storeToUpload });

// Route to handle image upload and table update
app.put('/api/updateImage/:id', updateImage.single('image'), (req, res) => {
  const { id } = req.params;

  const imagePath = req.file.path;

  // Execute an SQL query to update the table and store the image path in the database
  const query = 'UPDATE users SET image_url = ? WHERE id = ?';

  db.query(query, [imagePath, id], (error, result) => {
    if (error) {
      console.error('Error updating table:', error);
      res.status(500).json({ error: 'Failed to update the table.' });
    } else {
      res.status(200).json({ message: 'Table updated successfully.' });
    }
  });
});

app.use('/api/userImage', express.static(path.join(__dirname, 'uploads')));

app.post('/api/insertUser', (req, res) => {
  // const { username, password } = req.body;
  const { firstname, lastname, middlename, address, sex, birthdate, email, role, password } = req.body;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }
    const query = 'INSERT INTO users (firstname, lastname, middlename, address, sex, birthdate, email, role, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [firstname, lastname, middlename, address, sex, birthdate, email, role, hash], (err, result) => {
      if (err) {
        // console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  })
});

app.put('/api/resetPassword', (req, res) => {
  const { email, newPassword } = req.body;

  // Execute an SQL query to update the user's password in the database
  const query = 'UPDATE users SET password = ? WHERE email = ?';

  bcrypt.hash(newPassword, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return res.status(500).json({ error: 'Failed to reset password.' });
    }

    db.query(query, [hash, email], (error, result) => {
      if (error) {
        console.error('Error updating password:', error);
        return res.status(500).json({ error: 'Failed to reset password.' });
      }
      
      res.status(200).json({ message: 'Password reset successful.' });
    });
  });
});

app.post('/api/createProject', (req, res) => {
  const { projectID, projectName, startDate } = req.body;
  const query = 'INSERT INTO projects (projectID, projectName, startDate) VALUES (?, ?, ?)';
  db.query(query, [projectID, projectName, startDate], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    const insertedData = {
      projectID,
      projectName,
      startDate,
      budget: 0
    };
    res.status(200).json(insertedData);
  });
});

app.post('/api/createActivity', (req, res) => {
  const { actDate, activityID, activityName, budget } = req.body;
  const query = 'INSERT INTO activity (activityID, activityName, actDate, budget) VALUES (?, ?, ?, ?)';
  db.query(query, [activityID, activityName, actDate, budget], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'Activity added successfully' });
  });
});

app.post('/api/createObjectives', (req, res) => {
  const { title, projectID } = req.body;
  const query = 'INSERT INTO goal (goalID, title, projectID) VALUES (?, ?, ?)';

  db.query("SELECT id FROM goal ORDER BY id DESC LIMIT 1", (err, result) => {
    if (err) {
      console.log('Error retrieving last voucher number:', err);
      res.status(500).send('Error retrieving last voucher number');
    } else {
      let objectiveID = 1;
      if (result.length > 0) {
        objectiveID = parseInt(result[0].id) + 1;
      }
      const formattedGoalID = "OBJT" + objectiveID.toString().padStart(4, "0");
      db.query(query, [formattedGoalID, title, projectID], (err, result) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        } else {
          const insertedData = {
            goalID: formattedGoalID,
            id: result.insertId,
            title: title
          };
          res.status(200).json(insertedData);
        }
      });
    }
  });
});

app.post('/api/createOutcome', (req, res) => {
  const { outcome, goalID } = req.body;
  const query = 'INSERT INTO outcome (outcomeID, title, goalID) VALUES (?, ?, ?)';
  db.query("SELECT id FROM outcome ORDER BY id DESC LIMIT 1", (err, result) => {
    if (err) {
      console.log('Error retrieving last voucher number:', err);
      res.status(500).send('Error retrieving last voucher number');
    } else {
      let outcomeID = 1;
      if (result.length > 0) {
        outcomeID = parseInt(result[0].id) + 1;
      }
      const formattedOutcomeID = "OUTC" + outcomeID.toString().padStart(4, "0");
      db.query(query, [formattedOutcomeID, outcome, goalID], (err, result) => {
        if (err) {
          console.log("Error Here");
          return res.status(500).json({ error: err.message });
        } else {
          const insertedData = {
            goalID: goalID,
            outcomeID: formattedOutcomeID,
            title: outcome
          };
          res.status(200).json(insertedData);
        }
      });
    }
  });
});

app.post('/api/createOutput', (req, res) => {
  const { output, outcomeID } = req.body;
  const query = 'INSERT INTO output (outputID, title, objOutID) VALUES (?, ?, ?)';
  db.query("SELECT id FROM output ORDER BY id DESC LIMIT 1", (err, result) => {
    if (err) {
      console.log('Error retrieving last voucher number:', err);
      res.status(500).send('Error retrieving last voucher number');
    } else {
      let outputID = 1;
      if (result.length > 0) {
        outputID = parseInt(result[0].id) + 1;
      }
      const formattedOutputID = "OUTP" + outputID.toString().padStart(4, "0");
      db.query(query, [formattedOutputID, output, outcomeID], (err, result) => {
        if (err) {
          console.log("Error Here");
          return res.status(500).json({ error: err.message });
        } else {
          const insertedData = {
            outcomeID: outcomeID,
            outputID: formattedOutputID,
            title: output
          };
          res.status(200).json(insertedData);
        }
      });
    }
  });
});

app.post('/api/createIndicators', (req, res) => {
  const { indicator, iskpi, targetReach, actualReach, unit, format, freqreport, outputID } = req.body;
  const query = 'INSERT INTO indicator (indicatorID, indicator, iskpi, targetreach, unit, actualreach, format, freqreport, objOutID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
  db.query("show table status like 'indicator'", (err, result) => {
    if (result && result[0] && result[0].Rows !== undefined) {
      let indicatorID = result[0].Rows + 1; // Access the result[0].Rows value
      const formattedIndicatorID = "INDI" + indicatorID.toString().padStart(4, "0");
      db.query(query, [formattedIndicatorID, indicator, iskpi, targetReach, unit, actualReach, format, freqreport, outputID], (err, result) => {
        if (err) {
          console.log("Error Here");
          return res.status(500).json({ error: err.message });
        } else {
          const insertedData = {
            indicatorID: formattedIndicatorID,
            indicator: indicator,
            iskpi: iskpi,
            targetreach: targetReach,
            unit: unit,
            actualreach: actualReach,
            format: format,
            freqreport: freqreport,
            objOutID: outputID,
          };
          res.status(200).json(insertedData);
        }
      });
    } else {
      console.log('Error retrieving indicator rows:', result);
      res.status(500).send('Error retrieving indicator rows');
    }
  });
});

app.post('/api/createlogs', (req, res) => {
  const { date, description, user } = req.body;
  const sqlInsert = "INSERT INTO logs (date, description, user) VALUES (?, ?, ?)";
  db.query(sqlInsert, [date, description, user], (err, result) => {
    if (err) {
      res.status(500).send('Error inserting log data');
    } else {
      // console.log('Data inserted successfully');
      res.status(200).send('Data inserted successfully');
    }
  });
});

app.post('/api/createvoucher', (req, res) => {
  const {
    selectedDate, 
    payee, 
    details, 
    voucherNumber,
    entryTable,
    preparedby, 
    checkedby, 
    approvedby,
    status
  } = req.body;

  const insertVoucherDetails = "INSERT INTO vouchers (voucherNumber, date, payee, details, preparedby, checkedby, approvedby, ispreparedbysigned, ischeckedbysigned, isapprovedbysigned, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const insertJournalEntry = "INSERT INTO voucherjournalentry (voucherNumber, totalamount) VALUES (?, ?)";
  const insertDebit = "INSERT INTO voucherdebit (entryID, accountcode, accounttitle, amount) VALUES (?, ?, ?, ?)";
  const insertCredit = "INSERT INTO vouchercredit (entryID, accountcode, accounttitle, amount) VALUES (?, ?, ?, ?)";
  const isSuccess = false;
  // Retrieve the last voucherNumber from the vouchers table
  db.query("SELECT id FROM vouchers ORDER BY id DESC LIMIT 1", (err, result) => {
    if (err) {
      console.log('Error retrieving last voucher number:', err);
    } else {
      let lastVoucherNumber = 1;
      if (result.length > 0) {
        lastVoucherNumber = parseInt(result[0].id) + 1;
      }

      // Insert voucher details with the retrieved voucherNumber
      db.query(insertVoucherDetails, [lastVoucherNumber, selectedDate, payee, details, preparedby, checkedby, approvedby, 1, 0, 0, status], (err, result) => {
        if (err) {
          console.log('Error inserting voucher data:', err);
          isSuccess = false;
        } else {
          console.log('Voucher data inserted successfully');
          // Perform the next query after voucher data insertion
          db.query(insertJournalEntry, [lastVoucherNumber, 0], (err, result) => {
            if (err) {
              console.log('Error inserting journalentry data:', err);
              isSuccess = false;
            } else {
              console.log('Journal entry data inserted successfully');
              // Perform the next queries after journal entry data insertion
              entryTable.forEach((entry, index) => {
                if (entry.debit !== "") {
                  db.query(insertDebit, [lastVoucherNumber, entry.accountCode, entry.accountTitle, entry.debit], (err, result) => {
                    if (err) {
                      console.log('Error inserting debit data:', err);
                      isSuccess = false;
                    } else {
                      console.log('Debit data inserted successfully');
                    }
                  });
                } else {
                  db.query(insertCredit, [lastVoucherNumber, entry.accountCode, entry.accountTitle, entry.credit], (err, result) => {
                    if (err) {
                      console.log('Error inserting credit data:', err);
                      isSuccess = false;
                    } else {
                      console.log('Credit data inserted successfully');
                    }
                  });
                }
              });
            }
          });
        }
      });
    }
  });

  if (!isSuccess) {
    res.status(500).send('Error inserting voucher data');
  } else {
    res.status(200).send('Data inserted successfully');
  }
});

app.post('/api/createparticipants', (req, res) => {
  const currentDate = new Date();
  const { firstname, lastname, middlename, age, sex, cityMun, org, indicatorID } = req.body;
  const query = 'INSERT INTO partyindivdual (firstname, lastname, middlename, age, sex, cityMun, organization, indicatorID, participantsID, dateadded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

  db.query("SHOW TABLE STATUS LIKE 'partyindivdual'", (err, result) => {
    if (err) {
      // console.log("err");
      return res.status(500).json({ error: err.message });
    } else {
      if (result && result.length > 0) {
        const partyID = result[0].Rows + 1;
        const formattedPartyID = "PART" + partyID.toString().padStart(4, "0");

        db.query(query, [firstname, lastname, middlename, age, sex, cityMun, org, indicatorID, formattedPartyID, currentDate], (err, result) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          } else {
            const insertedData = {
              id: partyID,
              firstname: firstname, 
              lastname: lastname,
              middlename: middlename,
              age: age,
              sex: sex,
              organization: org,
              indicatorID: indicatorID,
              cityMun: cityMun
            };
            // console.log("success");
            res.status(200).json(insertedData);
          }
        });
      } else {
        res.status(500).json({ error: 'Failed to get table status' });
      }
    }
  });
});

app.post('/api/createBudget', (req, res) => {
  const { amount, source, date, projectID } = req.body;
  const query = 'INSERT INTO budgetlog (projectID, date, amount, source) VALUES (?, ?, ?, ?)';
  const queryUpdate = 'UPDATE projects SET budget = ? WHERE projectID = ?';
  const getBudget = 'SELECT budget FROM projects WHERE projectID = ?';
  db.query(query, [projectID, date, amount, source], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    db.query(getBudget, [projectID], (err, result) => {
      if (err) {
        res.status(500).json({ message: 'Internal server error' });
        return;
      }
      const newBudget = parseFloat(result[0].budget) + parseFloat(amount);

      db.query(queryUpdate, [newBudget, projectID], (err, result) => {
        if (err) {
          console.error('Error updating project:', err);
          res.status(500).json({ message: 'Internal server error' });
          return;
        }
  
        if (result.affectedRows === 0) {
          res.status(404).json({ message: 'Project not found' });
          return;
        }
  
        const insertedData = {
          projectID: projectID,
          date: date,
          source: source,
          amount: amount,
        };
        // console.log("success");
        res.status(200).json(insertedData);
      });
    });
  });
});

//  import
// API endpoint for uploading CSV
app.post('/api/upload/:tableId', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file was uploaded.' });
  }

  const currentDate = new Date();
  const file = req.file;
  const tableId = req.params.tableId;

  if (!tableId || !isValidTableId(tableId)) {
    return res.status(400).json({ error: 'Invalid tableId provided.' });
  }

  fs.createReadStream(file.path)
    .pipe(csv())
    .on('data', (data) => {
      // Process the data as needed (e.g., insert into a database)
      db.query('INSERT INTO partyindivdual SET ?', { ...data, indicatorID: tableId, dateadded: currentDate }, (error, results) => {
        if (error) {
          console.error('Error inserting row:', error);
        } else {
          console.log('Row inserted');
        }
      });
      console.log(data);
    })
    .on('end', () => {
      fs.unlinkSync(file.path); // Remove the uploaded file after processing
      res.status(200).json({ success: true });
    })
    .on('error', (error) => {
      console.error('Error processing CSV:', error);
      res.status(500).json({ error: 'Error processing CSV.' });
    });
});

// Helper function to validate the tableId parameter
function isValidTableId(tableId) {
  // Add validation logic here (e.g., check for expected format)
  return true; // Replace with actual validation
}
// Read

app.get('/api/team', (req, res) => {
  const sqlSelect = "SELECT firstname, middlename, lastname, role, email FROM users order by id asc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      // console.log('Error fetching members:', err);
      res.status(500).send('Error fetching members');
      console.log(result);
    } else {
      res.status(200).json(result);
    }
  });
});

app.get('/api/partners/:id', (req, res) => {
  const projectId = req.params.id;
  const sqlSelect = "SELECT amount, source, date FROM budgetlog WHERE projectId = ?";
  db.query(sqlSelect, projectId, (err, result) => {
    if (err) {
      console.log('Error fetching partners:', err);
      res.status(500).send('Error fetching partners');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/projects', (req, res) => {
  const sqlSelect = "SELECT * FROM projects order by id asc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      // console.log('Error fetching members:', err);
      res.status(500).send('Error fetching projects');
      console.log(result);
    } else {
      res.json(result);
      // console.log(result.data);
    }
  });
});

app.get('/api/activities', (req, res) => {
  const sqlSelect = "SELECT * FROM activity order by id asc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      res.status(500).send('Error fetching activities');
      console.log(result);
    } else {
      res.json(result);
    }
  });
});

app.get('/api/activities/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT act.*, act.budget - COALESCE(credit.totalAmount, 0) AS balance, COALESCE(credit.totalAmount, 0) AS totalCreditAmount FROM activity AS act LEFT JOIN (SELECT accountcode, SUM(amount) AS totalAmount FROM vouchercredit GROUP BY accountcode) AS credit ON act.activityID = credit.accountcode WHERE act.activityID LIKE ? and act.isDeleted = 0 ORDER BY act.id ASC";
  db.query(sqlSelect, [`${id}-%`], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/activityRecords/:id', (req, res) => {
  const id = req.params.id;
  const voucherCreditQuery = "SELECT * FROM vouchercredit where accountcode like ? order by id asc";
  const voucherDebitQuery = "SELECT * FROM voucherdebit where accountcode like ? order by id asc";
  let data = [];
  db.query(voucherCreditQuery, [id], (err, creditResult) => {
    if (err) {
      console.error('Error fetching credit data:', err);
      res.status(500).send('Error fetching data');
    } else {
      data = data.concat(creditResult.map(row => ({ ...row, type: "Credit" })));

      db.query(voucherDebitQuery, [id], (err, debitResult) => {
        if (err) {
          console.error('Error fetching debit data:', err);
          res.status(500).send('Error fetching data');
        } else {
          data = data.concat(debitResult.map(row => ({ ...row, type: "Debit" })));
          res.status(200).send(data);
        }
      });
    }
  });
});

app.get('/api/totalExpenses/:id', (req, res) => {
  const id = req.params.id;
  // const voucherCreditQuery = "SELECT * FROM vouchercredit where accountcode like ? order by id asc";
  const voucherCreditQuery = "SELECT activityID, activityName, budget, SUM(amount) FROM activity AS act JOIN vouchercredit AS vc ON act.activityID = vc.accountcode WHERE act.activityID = ?";
  // let data = 0;
  db.query(voucherCreditQuery, [id], (err, result) => {
    if (err) {
      console.error('Error fetching credit data:', err);
      res.status(500).send('Error fetching data');
    } else {
      // data = creditResult.map(row => row.amount).reduce((accumulator, currentValue) => accumulator + currentValue, 0);
      res.status(200).send(result);
    }
  });
});

app.get('/api/participants/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM partyindivdual where indicatorID like ? order by id asc";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/logs', (req, res) => {
  const sqlSelect = "SELECT * FROM logs order by id asc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      // console.log('Error fetching data logs:', err);
      res.status(500).send('Error fetching data logs');
      console.log(result);
    } else {
      res.json(result);
      // console.log(result.data);
    }
  });
});

app.get('/api/objectives/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM goal where projectID like ? and isDeleted = 0 order by id asc";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      console.log('Error fetching data:', err);
      res.status(500).send('Error fetching data');
    } else {
      if(result.length>0){
        console.log(result);
        res.json(result);
      }else{
        console.log(result);
        res.json([]);
      }
    }
  });
});

app.get('/api/outcomes/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM outcome where goalID like ? and isDeleted = 0 order by id asc";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/outputs/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM output WHERE objOutID = ? AND isDeleted = 0 ORDER BY id ASC";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      console.error('Error fetching output data:', err);
      res.status(500).send('Error fetching output data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/indicators/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM indicator where objOutID like ? and isDeleted = 0 order by id asc";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      // console.log('Error fetching data:', err);
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
      // console.log(result);
    }
  });
});

app.get('/api/indicatorData/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT year, targetReach, actualReach FROM indicatordata where indicatorID like ?";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      if(result.length>0){
        res.json(result);
      }else{
        res.json([]);
      }
    }
  });
});

app.get('/api/outcomeindicators/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM indicator where objOutID like ? and isDeleted = 0";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/activityDetails/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM activity where activityID like ?";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      // console.log('Error fetching data:', err);
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
      // console.log(result);
    }
  });
});

app.get('/api/indicatordetails/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM indicator where indicatorID like ?";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      // console.log('Error fetching data:', err);
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
      // console.log(result);
    }
  });
});

app.get('/api/projectDetails/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM projects where projectID like ?";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      // console.log('Error fetching data:', err);
      res.status(500).send('Error fetching data');
    } else {
      const objectValue = result[0];
      res.json(objectValue);
    }
  });
});

app.get('/api/voucherapprovals', (req, res) => {
  const sqlSelect = "SELECT * FROM vouchers order by id desc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      // console.log('Error fetching data logs:', err);
      res.status(500).send('Error fetching data logs');
      console.log(result);
    } else {
      res.json(result);
      // console.log(result.data);
    }
  });
});

app.get('/api/voucherrecord', (req, res) => {
  const sqlSelect = "SELECT * FROM vouchers order by id desc";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      // console.log('Error fetching data logs:', err);
      res.status(500).send('Error fetching data logs');
      console.log(result);
    } else {
      res.json(result);
      // console.log(result.data);
    }
  });
});

app.get('/api/vouchernumber', (req, res) => {
  const sqlSelect = "SELECT * FROM vouchers order by id desc limit 1";
  db.query(sqlSelect, (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data logs');
    } else {
      if(result.length>0){
        res.json({ row: result[0].id + 1 });
      }else{
        res.json({ row: 1 });
      }
    }
  });
});


app.get('/api/getExpenses/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM vouchercredit where accountcode like CONCAT(?, '%') order by id asc";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

app.get('/api/debitCredit/:id', (req, res) => {
  const id = req.params.id;
  const creditdata = "SELECT * FROM vouchercredit where entryID = ? order by id asc";
  const debitdata = "SELECT * FROM voucherdebit where entryID = ? order by id asc";
  let data = [];
  db.query(debitdata, [id], (err, creditResult) => {
    if (err) {
      console.error('Error fetching credit data:', err);
      res.status(500).send('Error fetching data');
    } else {
      data = data.concat(creditResult.map(row => ({ ...row, type: "Debit" })));

      db.query(creditdata, [id], (err, debitResult) => {
        if (err) {
          console.error('Error fetching debit data:', err);
          res.status(500).send('Error fetching data');
        } else {
          data = data.concat(debitResult.map(row => ({ ...row, type: "Credit" })));
          res.status(200).send(data);
        }
      });
    }
  });
});

app.get('/api/userData/:id', (req, res) => {
  const id = req.params.id;
  const sqlSelect = "SELECT * FROM users where email like ?";
  db.query(sqlSelect, [id], (err, result) => {
    if (err) {
      res.status(500).send('Error fetching data');
    } else {
      res.json(result);
    }
  });
});

// Update

app.put('/api/updateproject/:id', (req, res) => {
  const id = req.params.id;
  const { projectName, status, description } = req.body;

  const query = 'UPDATE projects SET projectName = ?, status = ?, description = ? WHERE projectID = ?';
  const values = [projectName, status, description, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating project:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Project not found' });
      return;
    }

    res.json({ message: 'Project updated successfully', projectName });
  });
});

app.put('/api/updateactivity/:id', (req, res) => {
  const id = req.params.id;
  const { activityName, selectedDate, status, budget } = req.body;

  const query = 'UPDATE activity SET activityName = ?, actDate = ?, status = ?, budget = ? WHERE activityID = ?';
  const values = [activityName, selectedDate, status, budget, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating Activity:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Activity not found' });
      return;
    }

    res.json({ message: 'Activity updated successfully', activityName });
  });
});


app.put('/api/updateIndicator/:id', (req, res) => {
  const id = req.params.id;
  const { indicatorName, targetReach, unit, format, freqReport } = req.body;

  const query = 'UPDATE indicator SET indicator = ?, targetreach = ?, unit = ?, format = ?, freqreport = ? WHERE indicatorID = ?';
  const values = [indicatorName, targetReach, unit, format, freqReport, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating indicator:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'indicator not found' });
      return;
    }

    res.json({ message: 'indicator updated successfully', indicatorName });
  });
});


app.put('/api/updateDeleteObjectives/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE goal SET isDeleted = ? WHERE id = ?';

  // Execute the update query
  db.query(query, [true, id], (err, result) => {
    if (err) {
      console.error('Error updating objective:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Objective not found' });
      return;
    }

    // Get the title from the updated objective
    const getTitleQuery = 'SELECT title FROM goal WHERE id = ?';
    db.query(getTitleQuery, [id], (err, result) => {
      if (err) {
        console.error('Error fetching title:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ message: 'Objective not found' });
        return;
      }

      const title = result[0].title;
      res.json({ message: 'Objective deleted successfully', title });
    });
  });
});

app.put('/api/updateDeleteOutcomes/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE outcome SET isDeleted = ? WHERE id = ?';

  // Execute the update query
  db.query(query, [true, id], (err, result) => {
    if (err) {
      console.error('Error updating outcome:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Outcome not found' });
      return;
    }

    // Get the title from the updated objective
    const getTitleQuery = 'SELECT title FROM outcome WHERE id = ?';
    db.query(getTitleQuery, [id], (err, result) => {
      if (err) {
        console.error('Error fetching title:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ message: 'Outcome not found' });
        return;
      }

      const title = result[0].title;
      res.json({ message: 'Outcome deleted successfully', title });
    });
  });
});

app.put('/api/updateDeleteOutputs/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE output SET isDeleted = ? WHERE id = ?';

  // Execute the update query
  db.query(query, [true, id], (err, result) => {
    if (err) {
      console.error('Error updating outcome:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Output not found' });
      return;
    }

    // Get the title from the updated objective
    const getTitleQuery = 'SELECT title FROM output WHERE id = ?';
    db.query(getTitleQuery, [id], (err, result) => {
      if (err) {
        console.error('Error fetching title:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ message: 'Output not found' });
        return;
      }

      const title = result[0].title;
      res.json({ message: 'Output deleted successfully', title });
    });
  });
});

app.put('/api/updateDeleteIndicator/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE indicator SET isDeleted = ? WHERE id = ?';

  // Execute the update query
  db.query(query, [true, id], (err, result) => {
    if (err) {
      console.error('Error updating indicator:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'indicator not found' });
      return;
    }

    // Get the title from the updated objective
    const getTitleQuery = 'SELECT indicator FROM indicator WHERE id = ?';
    db.query(getTitleQuery, [id], (err, result) => {
      if (err) {
        console.error('Error fetching title:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ message: 'indicator not found' });
        return;
      }

      const title = result[0].title;
      res.json({ message: 'Indicator deleted successfully', title });
    });
  });
});


app.put('/api/updateObjective/:id', (req, res) => {
  const id = req.params.id;
  const { editObjective} = req.body;

  const query = 'UPDATE goal SET title = ? WHERE goalID = ?';
  const values = [editObjective, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating objective:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'objective not found' });
      return;
    }

    res.json({ message: 'objective updated successfully', editObjective });
  });
});


app.put('/api/updateOutcome/:id', (req, res) => {
  const id = req.params.id;
  const { editOutcome } = req.body;

  const query = 'UPDATE outcome SET title = ? WHERE outcomeID = ?';
  const values = [editOutcome, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating outcome:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'outcome not found' });
      return;
    }

    res.json({ message: 'outcome updated successfully', editOutcome });
  });
});

app.put('/api/updateOutput/:id', (req, res) => {
  const id = req.params.id;
  const { editOutput } = req.body;

  const query = 'UPDATE output SET title = ? WHERE outputID = ?';
  const values = [editOutput, id];

  // Execute the update query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating output:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'output not found' });
      return;
    }

    res.json({ message: 'output updated successfully', editOutput });
  });
});

// Get all members
app.get('/api/members', (req, res) => {
  const query = 'SELECT * FROM users WHERE isDeleted = 0';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching members:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    res.json(results);
  });
});

// Update or delete a member
app.put('/api/updateDeleteMember/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE users SET isDeleted = 1 WHERE id = ?';

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error updating/deleting member:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'Member not found' });
      return;
    }

    res.json({ message: 'Member deleted successfully' });
  });
});

app.put('/api/updateDeleteActivity/:id', (req, res) => {
  const id = req.params.id;

  const query = 'UPDATE activity SET isDeleted = ? WHERE id = ?';

  // Execute the update query
  db.query(query, [true, id], (err, result) => {
    if (err) {
      console.error('Error updating activity:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }

    if (result.affectedRows === 0) {
      res.status(404).json({ message: 'activity not found' });
      return;
    }

    // Get the title from the updated objective
    const getTitleQuery = 'SELECT activityName FROM activity WHERE id = ?';
    db.query(getTitleQuery, [id], (err, result) => {
      if (err) {
        console.error('Error fetching title:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ message: 'activity not found' });
        return;
      }

      const title = result[0].activityName;
      res.json({ message: 'activity deleted successfully', title });
    });
  });
});



// Delete

// app.delete('/api/deleteObjectives/:id', (req, res) => {
//   const id = req.params.id;
//   const deleteQuery = "Delete"

//   // Perform the database deletion operation using an SQL DELETE statement
//   const sqlDelete = 'DELETE FROM your_table_name WHERE id = ?';
//   pool.query(sqlDelete, [id], (error, result) => {
//     if (error) {
//       console.error('Error deleting row:', error);
//       res.status(500).json({ success: false, error: 'Internal server error' });
//     } else {
//       if (result.affectedRows === 0) {
//         res.status(404).json({ success: false, error: 'Row not found' });
//       } else {
//         res.json({ success: true });
//       }
//     }
//   });
// });


app.listen(3001, () => {
  console.log("Running on port 3001");
});
