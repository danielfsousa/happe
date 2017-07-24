/**
 * GET /
 * Home page.
 */
exports.index = (req, res) => {
  if (req.user) {
    res.redirect('/conta');
  } else {
    res.redirect('/entrar')
  }
};
