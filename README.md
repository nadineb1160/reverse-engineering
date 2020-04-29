# Reverse Engineer 
This is an application has a login page that uses passport to authenticate the user and password. 

## Dependencies - package.json
```
    "bcryptjs": "2.4.3",
    "express": "^4.17.0",
    "express-session": "^1.16.1",
    "mysql2": "^1.6.5",
    "passport": "^0.4.0",
    "passport-local": "^1.0.0",
    "sequelize": "^5.8.6"
```

## Session - server.js
This creates a session middlware saved on the server-side.
Module directly reads and writes cookies on req/res.

Here is where we use our middleware to keep track of our user's login status
```
app.use(session({ secret: "keyboard cat", resave: true, saveUninitialized: true }));
```

### Options 
 express-session accepts properties in options object

- ``` resave ``` - forces session to be saved back to session store
- ``` saveUninitialized ``` - forces a session that is "uninitialized" to be saved to the store. A session is uninitialized when it is new but not modified.
- ``` secret ``` - used to sign the session ID cookie (required)

## Passport - server.js

- Express-compatible authentication middleware for Node.js

- Uses strategies to authenticate requests (verifying username and password)

- ``` passport.initialize() ``` - initialiaze to use passport in an Express application

- ``` passport.session() ``` - for usingpersistent login sessions.


## Passport - passport.js

- ``` var LocalStrategy = require("passport-local").Strategy; ``` - authenticates using usename and passord
- ``` passort.use(new LocalStrategy())```  - use local stratgey - login with username/email and password
- ``` db.User.findOne({where: {email: email}} ``` - find user with email

### Serialize:
Store id as cookie is user's brower
```
passport.serializeUser(function(user, cb) {
  cb(null, user);
});
```
### Deserialize:
Retrieve id from cookie
```
passport.deserializeUser(function(obj, cb) {
  cb(null, obj);
});
```

## Routes - api-routes.js
Call passport.authenticate() and specify stragey:
``` 
app.post("/api/login", passport.authenticate("local"),       function(req, res) {
    res.json(req.user);
});
```
If authenticatied, send to members page, otherwise error.

## Authenticate - isAuthenticated.js
Continue with request if user is logged in:
```
module.exports = function(req, res, next) {
    if (req.user) {
        return next();
    }
    return res.redirect("/");
}
```

## Signup - signup.js
Call ```signUpUser``` from form submit button with email and passord, which does a post to signup routes.
Redirect to members page if successful otherwise handle errors.
```
function signUpUser(email, password) {
    $.post("/api/signup", {
        email: email,
        password: password
    })
    .then(function(data) {
    window.location.replace("/members");
    // If there's an error, handle it by throwing up a bootstrap alert
    })
    .catch(handleLoginErr);
}
```

```handleLoginError```:
```
function handleLoginErr(err) {
    $("#alert .msg").text(err.responseJSON);
    $("#alert").fadeIn(500); 
  }
```
```fadeIn``` gradually changes opacity from hidden to visible

To redirect to new page:
window.location.replace("/members");

## Signup - api-routes.js
Login form is submitted to the server using POST method:
```
app.post("/api/signup", function(req, res) {
db.User.create({
    email: req.body.email,
    password: req.body.password
})
    .then(function() {
    res.redirect(307, "/api/login");
    })
    .catch(function(err) {
    res.status(401).json(err);
    });
});
```

The password is automatically hashed because of the User method addHook which automatically hashes their password before the user is created. Then the client is redirected to login if an error is not caught.  

Logout:
```
app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});
```

Get data to be used for client side (checks if user logged in):
```
app.get("/api/user_data", function(req, res) {
    if (!req.user) {
        res.json({});
    } else {
        res.json({
        email: req.user.email,
        id: req.user.id
      });
    }
  });
```

## User - user.js
Before the user is created we hash password:
``` 
User.addHook("beforeCreate", function(user) {
    user.password = bcrypt.hashSync(user.password, bcrypt.genSaltSync(10), null);
});
```
Custom method that checks unhashed password from user and hashed version stored in database:
```  
User.prototype.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
}; 
``` 

## Hash Info
A hash function takes in a password and returns a hash which is always the same length. 

We don't want to store sensitive data so we hash our password and store that hash.

A password can be converted into hash but not the other way around which is why it is good to store the hash itself.

If two users have the same password they would also have the same hash so to prevent this we add a salt before we hash it.

### Salt
Insures hash is always unique even if password is not unique.

We can then authenticate our users when they log in by hashing their submitted password and comparing that to the stored hash value.

### Bcrypt
- Neutalize brute force atttacks
- bcrypt(password, salt, cost) for hashing
- cost - defines number of rounds algorithm runs
- increase cost to be more resistent against attacks

### Resultant hash

Length: 60 charaters long

Characters:
```
./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$ 
```
- Once user is authenticated, passport session keeps them logged in
- Use local stratgey to authenticate users that are registered in DB

## HTML Pages
Custom middleware for checking user logged in
```
var isAuthenticated = require("../config/middleware/isAuthenticated");
```

Routes for "/" and "/login" check authentication:
```
if (req.user) {
    res.redirect("/members");
}
```
Otherwise it send to another file:
```
res.sendFile(path.join(__dirname, "../public/signup.html"));
```

The "/members" route is authenticated 
```
app.get("/members", isAuthenticated, function(req, res) {
    res.sendFile(path.join(__dirname, "../public/members.html"));
});
```
If a user who is not logged in tries to access this route they will be redirected to the signup page
