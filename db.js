const mysql= require('mysql2')
const dbConnection = mysql.createPool({
    host: '127.0.0.1',
    user: 'Mile',
    password: 'qweasdzxc',
    database: 'proiect',
    dateStrings: true
}).promise();
module.exports = dbConnection;