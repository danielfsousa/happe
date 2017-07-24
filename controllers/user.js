const bluebird = require('bluebird');
const crypto = bluebird.promisifyAll(require('crypto'));
const nodemailer = require('nodemailer');
const passport = require('passport');
const User = require('../models/User');

/**
 * GET /entrar
 * Login page.
 */
exports.getLogin = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Entrar'
  });
};

/**
 * POST /entrar
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  req.assert('email', 'Email inválido').isEmail();
  req.assert('password', 'A senha deve ser preenchida').notEmpty();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/entrar');
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/entrar');
    }
    req.logIn(user, err => {
      if (err) {
        return next(err);
      }
      const name = user.profile.name || '';
      req.flash('success', { msg: `Seja bem-vindo ${name}!` });
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
};

/**
 * GET /sair
 * Log out.
 */
exports.logout = (req, res) => {
  req.logout();
  res.redirect('/');
};

/**
 * GET /registrar
 * Signup page.
 */
exports.getSignup = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/signup', {
    title: 'Registrar'
  });
};

/**
 * POST /registrar
 * Create a new local account.
 */
exports.postSignup = (req, res, next) => {
  req.assert('email', 'Email inválido').isEmail();
  req.assert('password', 'A senha deve conter no mínimo 8 caracteres').len(8);
  req
    .assert('confirmPassword', 'As senhas não coincidem')
    .equals(req.body.password);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/registrar');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }
    if (existingUser) {
      req.flash('errors', { msg: 'Já existe uma conta com o email inserido.' });
      return res.redirect('/registrar');
    }
    user.save(err => {
      if (err) {
        return next(err);
      }
      req.logIn(user, err => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};

/**
 * GET /conta
 * Profile page.
 */
exports.getAccount = (req, res) => {
  res.render('account/profile', {
    title: 'Gerenciar Conta'
  });
};

/**
 * POST /conta/perfil
 * Update profile information.
 */
exports.postUpdateProfile = (req, res, next) => {
  req.assert('email', 'Por favor, digite um email válido.').isEmail();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/conta');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) {
      return next(err);
    }
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.website || '';
    user.save(err => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', {
            msg: 'O endereço de email já está associado à outra conta.'
          });
          return res.redirect('/conta');
        }
        return next(err);
      }
      req.flash('success', {
        msg: 'As informações do perfil foram atualizadas.'
      });
      res.redirect('/conta');
    });
  });
};

/**
 * POST /conta/senha
 * Update current password.
 */
exports.postUpdatePassword = (req, res, next) => {
  req.assert('password', 'A senha deve conter no mínimo 8 caracteres').len(8);
  req
    .assert('confirmPassword', 'As senhas não coincidem')
    .equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/conta');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) {
      return next(err);
    }
    user.password = req.body.password;
    user.save(err => {
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'A senha foi alterada.' });
      res.redirect('/conta');
    });
  });
};

/**
 * POST /conta/excluir
 * Delete user account.
 */
exports.postDeleteAccount = (req, res, next) => {
  User.remove({ _id: req.user.id }, err => {
    if (err) {
      return next(err);
    }
    req.logout();
    req.flash('info', { msg: 'Conta excluída.' });
    res.redirect('/');
  });
};

/**
 * GET /conta/desvincular/:provider
 * Unlink OAuth provider.
 */
exports.getOauthUnlink = (req, res, next) => {
  const provider = req.params.provider;
  User.findById(req.user.id, (err, user) => {
    if (err) {
      return next(err);
    }
    user[provider] = undefined;
    user.tokens = user.tokens.filter(token => token.kind !== provider);
    user.save(err => {
      if (err) {
        return next(err);
      }
      req.flash('info', {
        msg: `a conta do ${provider} foi desvinculada do seu perfil.`
      });
      res.redirect('/conta');
    });
  });
};

/**
 * GET /redefinir-senha/:token
 * Reset Password page.
 */
exports.getReset = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User.findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires')
    .gt(Date.now())
    .exec((err, user) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        req.flash('errors', {
          msg: 'O token para resetar a senha é inválido ou se expirou.'
        });
        return res.redirect('/esqueci-a-senha');
      }
      res.render('account/reset', {
        title: 'Alerar Senha'
      });
    });
};

/**
 * POST /redefinir-senha/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
  req.assert('password', 'A senha deve conter no mínimo 8 caracteres.').len(8);
  req.assert('confirm', 'As senhas não coincidem.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('back');
  }

  const resetPassword = () =>
    User.findOne({ passwordResetToken: req.params.token })
      .where('passwordResetExpires')
      .gt(Date.now())
      .then(user => {
        if (!user) {
          req.flash('errors', {
            msg: 'O token para resetar a senha é inválido ou se expirou.'
          });
          return res.redirect('back');
        }
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        return user.save().then(
          () =>
            new Promise((resolve, reject) => {
              req.logIn(user, err => {
                if (err) {
                  return reject(err);
                }
                resolve(user);
              });
            })
        );
      });

  const sendResetPasswordEmail = user => {
    if (!user) {
      return;
    }
    const transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'sousa.dfs@gmail.com',
      subject: 'Senha alterada - Supermercado HAPPE',
      text: `Olá,\n\nA senha da conta ${user.email} foi alterada com sucesso.\n`
    };
    return transporter.sendMail(mailOptions).then(() => {
      req.flash('success', { msg: 'A sua senha foi alterada com sucesso.' });
    });
  };

  resetPassword()
    .then(sendResetPasswordEmail)
    .then(() => {
      if (!res.finished) res.redirect('/');
    })
    .catch(err => next(err));
};

/**
 * GET /esqueci-a-senha
 * Forgot Password page.
 */
exports.getForgot = (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Esqueci a senha'
  });
};

/**
 * POST /esqueci-a-senha
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
  req.assert('email', 'Por favor, digite um email válido.').isEmail();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/esqueci-a-senha');
  }

  const createRandomToken = crypto
    .randomBytesAsync(16)
    .then(buf => buf.toString('hex'));

  const setRandomToken = token =>
    User.findOne({ email: req.body.email }).then(user => {
      if (!user) {
        req.flash('errors', {
          msg: 'Não existe nenhuma conta vinculada à esse email.'
        });
      } else {
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        user = user.save();
      }
      return user;
    });

  const sendForgotPasswordEmail = user => {
    if (!user) {
      return;
    }
    const token = user.passwordResetToken;
    const transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'sousa.dfs@gmail.com',
      subject: 'Alterar a senha - Supermercado HAPPE',
      text: `Você está recebendo esse email porque você (ou outra pessoa) fez a solicitação para alteração de senha.\n\n
        Por favor, clique no link abaixo ou copie e cole no seu navegador:\n\n
        http://${req.headers.host}/redefinir-senha/${token}\n\n
        Se você não fez essa requisição, ignore esse email e a sua senha permanecerá a mesma.\n`
    };
    return transporter.sendMail(mailOptions).then(() => {
      req.flash('info', {
        msg: `Enviamos um email para ${user.email} com as instruções para alterar a sua senha.`
      });
    });
  };

  createRandomToken
    .then(setRandomToken)
    .then(sendForgotPasswordEmail)
    .then(() => res.redirect('/esqueci-a-senha'))
    .catch(next);
};
