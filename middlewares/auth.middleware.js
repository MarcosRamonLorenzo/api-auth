const TokenHelper = require("../helpers/token.helper");

const auth = (req, res, next) => {
  // Comprobamos que han enviado el token tipo Bearer en el Header
  if (!req.headers.authorization) {
    return res.status(401).send({
      result: "KO",
      msg: "Cabecera de autenticación tipo Bearer no encontrada [Authorization: Bearer jwtToken]",
    });
  }

  // El formato es: Authorization: "Bearer JWT"
  const token = req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).send({
      result: "KO",
      msg: "Token de acceso JWT no encontrado dentro de la cabecera [Authorization: Bearer jwtToken]",
    });
  }

  // Verificamos que el token es correcto
  TokenHelper.decodificaToken(token)
    .then((userId) => {
      req.user = {
        id: userId,
        token: token,
      };
      return next();
    })
    .catch((response) => {
      res.status(response.status);
      res.json({
        result: "KO",
        msg: response.msg,
      });
    });
};

module.exports = {
 auth
}