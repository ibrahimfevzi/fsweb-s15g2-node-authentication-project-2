const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

  const { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, 8);
  const newUser = { username, password: hash, role_name };
  try {
    const user = await Users.add(newUser);
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});

router.post("/login", usernameVarmi, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */

  const { username, password } = req.body;

  function tokenBuilder(user) {
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name,
    };
    const options = {
      expiresIn: "1d",
    };
    return jwt.sign(payload, JWT_SECRET, options);
  }

  if (bcrypt.compareSync(password, req.user.password)) {
    const token = tokenBuilder(req.user);
    res.status(200).json({
      message: `${username} geri geldi!`,
      token,
    });
  }

  // next(); // Bu satırı kaldırın veya burada çağırmayın, zaten middleware sonunda çağrılacak
});

module.exports = router;
