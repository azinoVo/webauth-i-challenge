const server = require('./api server/server');

const port = process.env.PORT || 7000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
