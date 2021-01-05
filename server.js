// Importuri npm + Importuri fisiere

const express = require('express')
const path = require ('path')
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const dbConnection = require('./db');
const { body, validationResult } = require('express-validator');
const app = express()
const bodyParser = require('body-parser');
const PDFDocument = require('pdfkit');
const fs = require('fs');

app.use(bodyParser.urlencoded({extended: false}))
app.set('view-engine','ejs')
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('F:/REST API/'));

app.use(cookieSession({

    name: 'session',
    keys: ['key1', 'key2'],
    maxAge:  3600 * 1000 // 1 hour
}))

// ###############################################################     REGISTER     ##################################################################



// Apelul functiei /register:
// - Introduce datele citite din form in baza de date, parola este criptata pentru securitate.
app.post('/register',
    // Verifica daca datele introduse sunt specifice unei adrese de email, returnand un mesaj de eroare
    [body('user_email','Invalid email address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `login` WHERE `email`=?', [value])
        .then(([rows]) => {
            if(rows.length > 0){
                // Returneaza un mesaj de eroare in cazul in care email-ul exista deja in baza de date
                return Promise.reject('This E-mail already in use!');
            }
            return true;
        });
    }),
    // Verificari daca campurile nume si prenume sunt goale. Verifica daca campul parola are cel putin 6 caractere.
    body('user_name','Username is Empty!').trim().not().isEmpty(),
    body('user_firstname','Username is Empty!').trim().not().isEmpty(),
    body('user_pass','The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
],
(req,res,next) => {

    const validation_result = validationResult(req);
    const {user_name, user_firstname,user_email, user_pass } = req.body;
    const user_type="pacient";
    if(validation_result.isEmpty()){
        // password encryption (using bcryptjs)
        bcrypt.hash(user_pass, 12).then((hash_pass) => {
            // INSERTING USER INTO DATABASE
            dbConnection.execute("INSERT INTO `login`(`nume`, `prenume`,`email`,`parola`,`type`) VALUES(?,?,?,?,?)",[user_name,user_firstname,user_email, hash_pass, user_type])
            .then(result => {
                res.render('Login.ejs',{
                    login_errors:['Account Successfully Created!']
                });
            }).catch(err => {
                // THROW INSERTING USER ERROR'S
                if (err) throw err;
            });
        })
        .catch(err => {
            // THROW HASING ERROR'S
            if (err) throw err;
        })
    }
    else{
        // COLLECT ALL THE VALIDATION ERRORS
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING login-register PAGE WITH VALIDATION ERRORS
        res.render('Register.ejs',{
            register_error:allErrors,
            old_data:req.body
        });
    }
});

app.get('/register', (req,res)=>{
    if(!req.session.userID)
    {
        res.render('Register.ejs')
    }
    else
    {
        res.redirect('/cont')
    }
})

// ###################################################################################################################################################

// ###############################################################     REGISTER ADMIN     ############################################################

app.post('/registeradmin', 
    [
        body('email').isEmail().custom((value) => {
            return dbConnection.execute('SELECT `email` FROM `login` WHERE `email`=?', [value])
            .then(([rows]) => {
                if(rows.length > 0){
                    return Promise.reject('This E-mail already in use!');
                }
                return true;
            });
        }),
        body('name','Lastname is Empty!').trim().not().isEmpty(),
        body('pren','Firstname is Empty!').trim().not().isEmpty(),
        body('pass','The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
    ],// end of post data validation
    (req,res,next) => {
        if(!req.session.userID)
        {
            res.redirect('/login')
        }
        else
        {
        const validation_result = validationResult(req);
        const {name, pren,email, pass} = req.body;
        const ismedic=req.body.beMedic
        const issecr=req.body.beSecretary

        // IF validation_result HAS NO ERROR
        if(validation_result.isEmpty()){
            // password encryption (using bcryptjs)
            bcrypt.hash(pass, 12).then((hash_pass) => {
                if(ismedic=='1'){
                    const cabinet=req.body.cabinet
                dbConnection.execute('INSERT INTO `login`(`nume`, `prenume`,`email`,`parola`,`type`,`cabinet`) VALUES(?,?,?,?,"medic",?)',[name,pren,email,hash_pass,cabinet])
                .then(result => {
                    res.render('Administrator.ejs',{
                    admin_reg:['Account created successfully!']
                    });

                   
                }).catch(err => {
                    // THROW INSERTING USER ERROR'S
                    if (err) throw err;
                });
                }
                else
                {
                    dbConnection.execute('INSERT INTO `login`(`nume`, `prenume`,`email`,`parola`,`type`) VALUES(?,?,?,?,"secretary")',[name,pren,email,hash_pass])
                    .then(result => {
                        res.render('Administrator.ejs',{
                        admin_reg:['Account created successfully!']
                        });
    
                        
                    }).catch(err => {
                        // THROW INSERTING USER ERROR'S
                        if (err) throw err;
                    });
                }
            })
            .catch(err => {
                // THROW HASING ERROR'S
                if (err) throw err;
            })
        }
        else{
            // COLLECT ALL THE VALIDATION ERRORS
            let allErrors = validation_result.errors.map((error) => {
                return error.msg;
            });
            // RENDERING login-register PAGE WITH VALIDATION ERRORS
            res.render('Administrator.ejs',{
                admin_reg:allErrors,
                old_data:req.body
            });
        }
    }
    
})

// ###################################################################################################################################################

// ###############################################################     LOGIN     #####################################################################

// Verifica datele introduse cu cele existente in baza de date si redirectioneaza la pagina care trebuie
app.post('/login', [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `login` WHERE `email`=?', [value])
        .then(([rows]) => {
            if(rows.length == 1){ 
                return true;        
            }
            return Promise.reject('Invalid user!');     
        });
    }),
    body('user_pass','Password is empty!').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const {user_pass, user_email} = req.body;
    if(validation_result.isEmpty()){
        
        dbConnection.execute("SELECT * FROM `login` WHERE `email`=?",[user_email])
        .then(([rows]) => {
            rows.map((result)=>{
            bcrypt.compare(user_pass, result.parola).then(compare_result => {
                if(compare_result === true){
                    req.session.isLoggedIn = true;
                    req.session.userID = result.id;
                        res.redirect('/')       
                }
                else{
                    res.render('Login.ejs',{ 
                        login_errors:['Invalid user!']
                    });
                }
            })
            .catch(err => {
                if (err) throw err;
            });
        })

        }).catch(err => {
            if (err) throw err;
        });
    }
    else{
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // RENDERING login-register PAGE WITH LOGIN VALIDATION ERRORS
        res.render('Login.ejs',{
            login_errors:allErrors
        });
    }
});

app.get('/login',(req,res)=>{
    if(!req.session.userID)
    {
        res.render('Login.ejs')
    }
    else
    {
        res.redirect('/cont')
    }
})

// ###################################################################################################################################################

// ###############################################################     LOGOUT     ####################################################################

app.get('/logout',(req,res)=>{
    if(req.session.userID)
    {
        req.session = null;
        res.redirect('/');
    }
    else
    {
        res.redirect('/');
    }
});
 
// ##################################################################################################################################################
 
// ###############################################################     PACIENT     ##################################################################

app.post('/pacient',(req, res)=>{ 
    const nume= req.body.nume
    const prenume= req.body.pren
    const varsta = req.body.age
    const adresa = req.body.dom
    const descriere = req.body.desc 
    const nrtelefon= req.body.tel
    const queryString="INSERT INTO programare(nume,prenume,varsta,adresa,telefon,descriere) VALUES(?,?,?,?,?,?)"
    dbConnection.query(queryString,[nume, prenume, varsta, adresa, nrtelefon, descriere],(err, results, fields)=>{
        if(err){
            res.sendStatus(500)
            console.log(err)
        }        
    })
    res.redirect('/cont')  
})


// Unde dumnezeu vine asta???
app.post('/tarif',(req,res)=>{
    const consultatie=req.body.tar_consult
    const interventie=req.body.tar_interventie
    const queryString="UPDATE tarife SET consultatie=?, interventie=?"
    dbConnection.query(queryString,[consultatie,interventie],(err, results, fields)=>{
        if(err){
            res.sendStatus(500)
            console.log(err)
            return 
        }
    })
    res.redirect('/cont')
})

// ###################################################################################################################################################

app.post('/delete',(req,res)=>{
    const id= req.body.id
    const confirm = req.body.confirm
    if(confirm == "confirm"){
        dbConnection.execute('delete from orar where id=?',[id])
        res.redirect('/cont')
    }
    else
    {
        res.redirect('/cont')
    }
})

app.post('/modify',(req,res)=>{
    const data=req.body.data
    const ora=req.body.ora
    const id=req.body.id
    const cabinet=req.body.cabinet
    dbConnection.query('update orar set data=?, ora=?, cabinet=? where id=?',[data, ora, cabinet, id],(err,req,res)=>{
        if(err){
            res.sendStatus(500)
            console.log(err)
        }
    })
    res.redirect('/cont')
}) 

app.post('/adauga',(req,res)=>{
    const id=req.body.id
    const ora=req.body.ora
    const data=req.body.data
    const medic=req.body.medic
    const nume=req.body.nume
    const prenume=req.body.prenume
    const cabinet=req.body.cabinet
    if(!ora && !data && !medic)
    {
        console.log('Nu ati introdus toate campurile!')
    }
    else
    {
        dbConnection.query('call programari(?,?,?,?,?,?,?)',[data, ora, nume, prenume, medic, id, cabinet])
        res.redirect('/cont')
    } 
})

app.post('/contdoc',(req,res)=>{
    const nume=req.body.search3
    dbConnection.execute("SELECT total, numeMedic, dataConsult FROM consultatie_medic WHERE numeMedic=?",[nume]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM consultatie_medic WHERE numeMedic=?',[nume]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total,
                test_6:[nume]
            })
        })
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""],
                test_6:[nume]
            }) 
        }        
        })
})

app.post('/yearsearch',(req,res)=>{
    const nume=req.body.savename
    const year=req.body.year+'-01-01'
    dbConnection.execute("SELECT total, numeMedic, dataConsult FROM consultatie_medic WHERE numeMedic=? AND YEAR(dataConsult)=YEAR(?)",[nume,year]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic 
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM consultatie_medic WHERE numeMedic=? AND YEAR(dataConsult)=YEAR(?)',[nume,year]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total,
            })
        }) 
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""],
            }) 
        }        
        })
})

app.post('/monthsearch',(req,res)=>{
    const nume=req.body.savename
    const month="2020-"+req.body.month+"-01"
    dbConnection.execute("SELECT total, numeMedic, dataConsult FROM consultatie_medic WHERE numeMedic=? AND MONTH(dataConsult)=MONTH(?)",[nume,month]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM consultatie_medic WHERE numeMedic=? AND MONTH(dataConsult)=MONTH(?)',[nume,month]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total
            })
        })
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""]
            }) 
        }         
        })
})

app.post('/daysearch',(req,res)=>{
    const nume=req.body.savename
    const day=req.body.day
    dbConnection.execute("SELECT total, numeMedic, dataConsult FROM consultatie_medic WHERE numeMedic=? AND dataConsult=?",[nume,day]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM consultatie_medic WHERE numeMedic=? AND dataConsult=?',[nume,day]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total
            })
        })
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""]
            }) 
        }        
        })
})

// ###############################################################     MEDIC     #####################################################################

app.post('/medic',(req,res)=>{
    const nume=req.body.nume
    const prenume=req.body.pren
    const varsta=req.body.age
    const gender=req.body.Gender
    const actiden=req.body.act
    const cnp=req.body.cnp
    const adresa=req.body.adr
    const mediu=req.body.mediu
    const telefon=req.body.telefon
    const judet=req.body.jud
    const localitate=req.body.loc
    const tara=req.body.tara
    const categProf=req.body.ocupatie
    const locmunca=req.body.munca
    const medicfam=req.body.med
    const telefonmedic=req.body.tel
    const examinare=req.body.detalii
    var bilet=Number(req.body.bilet)
    var radiologie=Number(req.body.radiologie)
    var laborator=Number(req.body.labo)
    var spital=Number(req.body.spital)
    var other=Number(req.body.other)
    if(bilet != 1){
        bilet = 0
    }
    if(radiologie != 1){
        radiologie = 0
    }
    if(laborator != 1){
        laborator = 0
    }
    if(spital != 1){
        spital = 0
    }
    if(other != 1){
        other = 0
    }
    var scrisoaremed=Number(req.body.scrisoare)
    if(scrisoaremed != 1){
        scrisoaremed = 0
    }
    var medicamente=req.body.medicamente
    if(scrisoaremed != 1){
        medicamente='NULL'
    }
    const total=req.body.total
    const numMedic=req.body.numemedic
    dbConnection.execute('select id from consultatie_medic where CNP=?',[cnp]).then(([rows])=>{
        if(rows != 0){
            rows.map((result)=>{
                const queryString="call modificare_consultatie(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURDATE())"
                dbConnection.query(queryString,[result.id, nume, prenume, varsta, gender,actiden, cnp, tara, judet, localitate, adresa, mediu, telefon, categProf, locmunca, medicfam, telefonmedic, examinare,bilet, radiologie, laborator, spital, other, scrisoaremed, medicamente, total, numMedic],(err, results, fields)=>{
                    if(err){
                        res.sendStatus(500)
                        console.log(err)
                        return 
                    }
                })
                res.redirect('/cont')
                })
            
        }
        else
        {
            const queryString="call inserare_consultatie(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURDATE())"
                dbConnection.query(queryString,[ nume, prenume, varsta, gender,actiden, cnp, tara, judet, localitate, adresa, mediu, telefon, categProf, locmunca, medicfam, telefonmedic, examinare,bilet, radiologie, laborator, spital, other, scrisoaremed, medicamente, total, numMedic],(err, results, fields)=>{
                    if(err){
                        res.sendStatus(500)
                        console.log(err)
                        return 
                    }
                })
                res.redirect('/cont')
        }
    })
})

// ###################################################################################################################################################

// ###############################################################     SECRETARY     #################################################################

app.post('/printpdf',(req, res)=>{
    const nume=req.body.nume
    const prenume=req.body.prenume
    const varsta=req.body.varsta
    const gender=req.body.gender
    const ci=req.body.ci
    const cnp=req.body.cnp
    const tara=req.body.tara
    const judet=req.body.judet
    const localitate=req.body.localitate
    const adresa=req.body.adresa
    const mediu=req.body.mediu
    const telefon=req.body.telefon
    const catprof=req.body.catprofes
    const ocupatie=req.body.ocupatie
    const medfam=req.body.medfam
    const telemed=req.body.telemed
    const examinare=req.body.examinare
    const bilettrimitere=req.body.bilettrimit
    const radiologie=req.body.radiolog
    const laborator=req.body.laborat
    const spital=req.body.spital
    const other=req.body.other
    const scrmed=req.body.scrmed
    const medicamente=req.body.medicamente
    const total=req.body.total

    var pdfDoc = new PDFDocument({compress:false});
    
    pdfDoc.text("Nume: "+nume, { lineBreak : true });
    pdfDoc.text("Prenume: "+prenume, { lineBreak : true });
    pdfDoc.text("Varsta: "+varsta, { lineBreak : true });
    pdfDoc.text("Sex: "+gender, { lineBreak : true });
    pdfDoc.text("Card identitate: "+ci, { lineBreak : true });
    pdfDoc.text("CNP: "+cnp, { lineBreak : true });
    pdfDoc.text("Tara: "+tara, { lineBreak : true });
    pdfDoc.text("Judet: "+judet, { lineBreak : true });
    pdfDoc.text("Localitate: "+localitate, { lineBreak : true });
    pdfDoc.text("Adresa: "+adresa, { lineBreak : true });
    pdfDoc.text("Mediu: "+mediu, { lineBreak : true });
    pdfDoc.text("Telefon: "+telefon, { lineBreak : true });
    pdfDoc.text("Categorie Profesionala: "+catprof, { lineBreak : true });
    pdfDoc.text("Ocupatie: "+ocupatie, { lineBreak : true });
    pdfDoc.text("Medic Familie: "+medfam, { lineBreak : true });
    pdfDoc.text("Telefon medic: "+telemed, { lineBreak : true });
    pdfDoc.text("Examinare: "+examinare, { lineBreak : true });
    pdfDoc.text(bilettrimitere +" "+ radiologie +" "+ laborator + " " + spital + " " + other, { lineBreak : true });
    pdfDoc.text(scrmed +" "+ medicamente, { lineBreak : true }); 
    pdfDoc.end();
    pdfDoc.pipe(fs.createWriteStream('F:/REST API/SampleDocument.pdf').on('finish', function () {
        res.sendFile('F:/REST API/SampleDocument.pdf')
      }));
    
})

app.post('/semiprint',(req,res)=>{
    const nume=req.body.nume
    const prenume=req.body.prenume
    const varsta=req.body.varsta
    const telefon=req.body.telefon
    const examinare=req.body.examinare
    var pdfDoc = new PDFDocument({compress:false});
    
    pdfDoc.text("Nume: "+nume, { lineBreak : true });
    pdfDoc.text("Prenume: "+prenume, { lineBreak : true });
    pdfDoc.text("Varsta: "+varsta, { lineBreak : true });
    pdfDoc.text("Telefon: "+telefon, { lineBreak : true });
    pdfDoc.text("Examinare: "+examinare, { lineBreak : true });
    pdfDoc.end();
    pdfDoc.pipe(fs.createWriteStream('F:/REST API/SemiDocument.pdf').on('finish', function () {
        res.sendFile('F:/REST API/SemiDocument.pdf')
      }));
})

app.post('/totalprint',(req,res)=>{
    const consultatie=req.body.examinare
    const radiologie=req.body.radiolog
    const laborator=req.body.laborat
    const spital=req.body.spital
    const other=req.body.other
    const total=req.body.total
    var consult=[]
    var radio=[]
    var lab=[]
    var spit=[]
    var oth=[]
    dbConnection.execute('SELECT * FROM tarife').then(([rows])=>{
        rows.map((result)=>{
            if(consultatie != "") 
            {
                consult.push("Aveti o consultatie / 50 RON")
            }
            if(radiologie == "Radiologie")
            {
                radio.push("Aveti trimitere catre Radiologie / 150 RON")
            }
            if(laborator == "Laborator")
            {
                lab.push("Aveti trimitere catre Laborator / 150 RON")
            }
            if(spital == "Spital")
            {
                spit.push("Aveti trimitere catre Spital / 150 RON")
            }
            if(other == "Altele")
            {
                oth.push("Aveti trimitere catre Altele / 150 RON")
            }
                var pdfDoc = new PDFDocument({compress:false});
                pdfDoc.text("Lista preturi: ", { lineBreak : true });
                pdfDoc.text(radio, { lineBreak : true });
                pdfDoc.text(lab, { lineBreak : true });
                pdfDoc.text(spit, { lineBreak : true });
                pdfDoc.text(oth, { lineBreak : true });
                pdfDoc.text("Total: "+total, { lineBreak : true });
                pdfDoc.end();
                pdfDoc.pipe(fs.createWriteStream('F:/REST API/TotalDocument.pdf').on('finish', function () {
                    res.sendFile('F:/REST API/TotalDocument.pdf')
                  }));
        })
    })
})

// ###################################################################################################################################################

// ###############################################################     ADMIN     #####################################################################

app.post('/admmedsrc',(req,res)=>{
    const nume=req.body.search2
    dbConnection.execute("SELECT total, numeMedic, dataConsult FROM consultatie_medic WHERE numeMedic=?",[nume]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM consultatie_medic WHERE numeMedic=?',[nume]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('Administrator_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total,
                test_6:[nume]
            })
        })
        } 
        else
        {
            res.render('Administrator_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""],
                test_6:[nume]
            }) 
        }        
        })
})

app.post('/admcabsrc',(req,res)=>{
    const nume=req.body.search2  
    dbConnection.execute("SELECT consultatie_medic.total, consultatie_medic.numeMedic, consultatie_medic.dataConsult FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=?",[nume]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute("SELECT SUM(consultatie_medic.total) as fulltotal FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=?",[nume]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('Administrator_CabSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total,
                test_6:[nume]
            })
        })
        } 
        else
        {
            res.render('Administrator_CabSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi nimic!"],
                test_5:[""],
                test_6:[nume]
            }) 
        }        
    })
})

app.post('/yearsearchcab',(req,res)=>{
    const nume=req.body.savename
    const year=req.body.year+'-01-01'
    dbConnection.execute("SELECT consultatie_medic.total, consultatie_medic.numeMedic, consultatie_medic.dataConsult FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND YEAR(consultatie_medic.dataConsult)=YEAR(?)",[nume,year]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic 
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND YEAR(dataConsult)=YEAR(?)',[nume,year]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total,
            })
        }) 
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""],
            }) 
        }        
        })
})

app.post('/monthsearchcab',(req,res)=>{
    const nume=req.body.savename
    const month="2020-"+req.body.month+"-01"
    dbConnection.execute("SELECT consultatie_medic.total, consultatie_medic.numeMedic, consultatie_medic.dataConsult FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND MONTH(consultatie_medic.dataConsult)=MONTH(?)",[nume,month]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND MONTH(dataConsult)=MONTH(?)',[nume,month]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total
            })
        })
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""]
            }) 
        }         
        })
})

app.post('/daysearchcab',(req,res)=>{
    const nume=req.body.savename
    const day=req.body.day
    dbConnection.execute("SELECT consultatie_medic.total, consultatie_medic.numeMedic, consultatie_medic.dataConsult FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND consultatie_medic.dataConsult=?",[nume,day]).then(([rows])=>{ 
        if(rows != 0){      
        var info_1 = rows.map(information =>{
            return information.total
        })
        var info_2 = rows.map(information2 =>{
            return information2.numeMedic
        })
        var info_3 = rows.map(information3 =>{
            return information3.dataConsult 
        })
        dbConnection.execute('SELECT SUM(total) as fulltotal FROM proiect.consultatie_medic inner join proiect.login on login.nume=consultatie_medic.numeMedic WHERE login.cabinet=? AND dataConsult=?',[nume,day]).then(([rows])=>{
            var total=rows.map(information4=>{
                return 'Total: '+information4.fulltotal
            })
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:[""],
                test_5:total
            })
        })
        } 
        else
        {
            res.render('SecretaryScreen_MedSearch.ejs',{
                test_1:info_1,
                test_2:info_2,
                test_3:info_3,
                test_4:["Nu am putut gasi pe nimeni!"],
                test_5:[""]
            }) 
        }        
        })
})

app.post('/searchpacient',(req, res)=>{
    const arr=req.body.search2
    var index = arr.indexOf(" ");
    var nume = arr.substr(0, index);
    var prenume = arr.substr(index + 1);
    dbConnection.execute("SELECT * FROM consultatie_medic WHERE nume=? AND prenume=?",[nume,prenume]).then(([rows])=>{
        if(rows != 0){
            rows.map((result)=>{ 
                var info_1 = rows.map(information =>{
                    return information.id
                })
                var info_2 = rows.map(information2 =>{
                    return information2.nume
                })
                var info_3 = rows.map(information3 =>{
                    return information3.prenume 
                })
                var info_4 = rows.map(information4 =>{
                    return information4.varsta
                })
                var info_5 = rows.map(information5 =>{
                    return information5.gender
                })
                var info_6 = rows.map(information6 =>{
                    return information6.CI
                })
                var info_7 = rows.map(information7 =>{
                    return information7.CNP
                })
                var info_8 = rows.map(information8 =>{
                    return information8.tara
                })
                var info_9 = rows.map(information9 =>{
                    return information9.judet
                })
                var info_10 = rows.map(information10 =>{
                    return information10.localitate
                })
                var info_11 = rows.map(information11 =>{
                    return information11.adresa
                })
                var info_12 = rows.map(information12 =>{
                    return information12.mediu
                })
                var info_13 = rows.map(information13 =>{
                    return information13.telefon
                })
                var info_14 = rows.map(information14 =>{
                    return information14.catProf
                })
                var info_15 = rows.map(information15 =>{
                    return information15.ocupatie
                })
                var info_16 = rows.map(information16 =>{
                    return information16.medFamilie
                })
                var info_17 = rows.map(information17 =>{
                    return information17.telefonMed
                })
                var info_18= rows.map(information18 =>{
                    return information18.examinare
                })
                var info_19 = []
                var info_20 = []
                var info_21 = []
                var info_22 = []
                var info_23 = []
                var info_24= ['Are scrisoare medicala cu urmatoarele:']
                if(JSON.stringify(Object.values(result.bilet_trimitere)) == '[1]'){
                    info_19.push('Are bilet de trimitere catre:')
                    if(JSON.stringify(Object.values(result.radiologie))=='[1]'){
                        info_20.push('Radiologie')
                    }
                    else{
                        info_20.push('')
                    }
                    if(JSON.stringify(Object.values(result.laborator))=='[1]'){
                        info_21.push('Laborator')
                    }
                    else{
                        info_21.push('')
                    }
                    if(JSON.stringify(Object.values(result.spital))=='[1]'){
                        info_22.push('Spital')
                    }
                    else{
                        info_22.push('')
                    }
                    if(JSON.stringify(Object.values(result.other))=='[1]'){
                        info_23.push('Altele')
                    }
                    else{
                        info_23.push('')
                    }
                    if(JSON.stringify(Object.values(result.scrMedicala)) =='[1]'){
                        var info_24= ['Are scrisoare medicala:']
                        var info_25= rows.map(information25 =>{
                            return information25.medicamente
                        })
                        var info_26= rows.map(information26 =>{
                            return information26.total
                        })
                        res.render('SecretaryScreen_SearchP.ejs',{
                            test_1:info_1,
                            test_2:info_2,
                            test_3:info_3,
                            test_4:info_4,
                            test_5:info_5,
                            test_6:info_6,
                            test_7:info_7,
                            test_8:info_8,
                            test_9:info_9,
                            test_10:info_10,
                            test_11:info_11,
                            test_12:info_12,
                            test_13:info_13,
                            test_14:info_14,
                            test_15:info_15,
                            test_16:info_16,
                            test_17:info_17,
                            test_18:info_18,
                            test_19:info_19,
                            test_20:info_20,
                            test_21:info_21,
                            test_22:info_22,
                            test_23:info_23,
                            test_24:info_24,
                            test_25:info_25,
                            test_26:info_26
                        })
                    }
                    else
                    {
                        var info_24= ['Nu are scrisoare medicala!']
                        var info_25= ['']
                        var info_26= rows.map(information26 =>{
                            return information26.total
                        })
                        res.render('SecretaryScreen_SearchP.ejs',{
                            test_1:info_1,
                            test_2:info_2,
                            test_3:info_3,
                            test_4:info_4,
                            test_5:info_5,
                            test_6:info_6,
                            test_7:info_7,
                            test_8:info_8,
                            test_9:info_9,
                            test_10:info_10,
                            test_11:info_11,
                            test_12:info_12,
                            test_13:info_13,
                            test_14:info_14,
                            test_15:info_15,
                            test_16:info_16,
                            test_17:info_17,
                            test_18:info_18,
                            test_19:info_19,
                            test_20:info_20,
                            test_21:info_21,
                            test_22:info_22,
                            test_23:info_23,
                            test_24:info_24,
                            test_25:info_25,
                            test_26:info_26
                        }) 
                    }
                }
                else
                {
                    if(JSON.stringify(result.scrMedicala)=='[1]'){
                        var info_24= ['Are scrisoare medicala cu urmatoarele:']
                        var info_25= rows.map(information25 =>{
                            return information25.medicamente
                        })
                        var info_26= rows.map(information26 =>{
                            return information26.total
                        })
                        res.render('SecretaryScreen_SearchP.ejs',{
                            test_1:info_1,
                            test_2:info_2,
                            test_3:info_3,
                            test_4:info_4,
                            test_5:info_5,
                            test_6:info_6,
                            test_7:info_7,
                            test_8:info_8,
                            test_9:info_9,
                            test_10:info_10,
                            test_11:info_11,
                            test_12:info_12,
                            test_13:info_13,
                            test_14:info_14,
                            test_15:info_15,
                            test_16:info_16,
                            test_17:info_17,
                            test_18:info_18,
                            test_19:info_19,
                            test_20:info_20,
                            test_21:info_21,
                            test_22:info_22,
                            test_23:info_23,
                            test_24:info_24,
                            test_25:info_25,
                            test_26:info_26
                        })
                    }
                    else
                    {
                        var info_24= ['Nu are scrisoare medicala!']
                        var info_25= ['']
                        var info_26= rows.map(information26 =>{
                            return information26.total
                        })
                        res.render('SecretaryScreen_SearchP.ejs',{
                            test_1:info_1,
                            test_2:info_2,
                            test_3:info_3,
                            test_4:info_4,
                            test_5:info_5,
                            test_6:info_6,
                            test_7:info_7,
                            test_8:info_8,
                            test_9:info_9,
                            test_10:info_10,
                            test_11:info_11,
                            test_12:info_12,
                            test_13:info_13,
                            test_14:info_14,
                            test_15:info_15,
                            test_16:info_16,
                            test_17:info_17,
                            test_18:info_18,
                            test_19:info_19,
                            test_20:info_20,
                            test_21:info_21,
                            test_22:info_22,
                            test_23:info_23,
                            test_24:info_24,
                            test_25:info_25,
                            test_26:info_26
                        }) 
                    }
                } 
            })
        }
        else
        {
            res.render('SecretaryScreen_SearchP.ejs',{
                noprog:["Pacientul cautat nu a fost consultat sau nu exista!"]
            })
        }
    })
})

// ###################################################################################################################################################

// ###############################################################     ACCOUNTS     ##################################################################

app.get('/cont', (req,res)=>{
    if(!req.session.userID)
    {
        res.redirect('/')
    }
    else
    {
        dbConnection.execute('SELECT * FROM login WHERE id=?',[req.session.userID]).then(([rows])=>{
            rows.map((result)=>{
                if (result.type =='medic')
                {
                    dbConnection.execute('SELECT  orar.data, orar.ora, orar.nume, orar.prenume, orar.numeMedic FROM orar INNER JOIN login ON login.nume=orar.numeMedic WHERE login.id=? AND data=CURDATE() ORDER BY ora',[req.session.userID]).then(([rows])=>{
                        if(rows.length == 0)
                        {
                            res.render('MedicScreen.ejs',{
                                progs:["Nu exista pacienti programati!"]
                            })
                        }
                        else
                        {   
                            var info = rows.map(information =>{
                                return  'Data: '+information.data+' | '+'Ora: '+information.ora+' | Numele pacientului: '+information.nume+' '+information.prenume
                            })
                            res.render('MedicScreen.ejs',{
                                progs:info
                            }) 
                        }
                    })
                }
                else if(result.type === 'administrator')
                {
                    res.render('Administrator.ejs')
                }
                else if(result.type === 'secretary')
                {
                    var contor=1
                    dbConnection.execute('SELECT * FROM programare').then(([rows])=>{
                        if(rows==0){
                            contor=0
                        }
                        var info_1 = rows.map(information =>{
                            return information.nume
                        })
                        var info_2 = rows.map(information2 =>{
                            return information2.prenume
                        })
                        var info_3 = rows.map(information3 =>{
                            return information3.varsta
                        })
                        var info_4 = rows.map(information4 =>{
                            return information4.adresa
                        })
                        var info_5 = rows.map(information5 =>{
                            return information5.telefon
                        })
                        var info_6 = rows.map(information6 =>{
                            return information6.descriere
                        })
                        var info_7 = rows.map(information6 =>{
                            return information6.id
                        })
                    dbConnection.execute('SELECT * FROM orar').then(([rows])=>{
                        var info = rows.map(information =>{
                            return information.ora
                        })
                        var info2 = rows.map(information2 =>{
                            return information2.nume
                        })
                        var info3 = rows.map(information3 =>{
                            return information3.prenume
                        })
                        var info4 = rows.map(information4 =>{
                            return information4.ID
                        })
                        var info5 = rows.map(information5 =>{
                            return information5.data
                        })
                        var info6 = rows.map(information6 =>{
                            return information6.numeMedic
                        })
                        var info7=rows.map(information7 =>{
                            return information7.cabinet
                        })
                        if(rows==0 && contor==0){
                            res.render('SecretaryScreen.ejs',{
                                noorar:["Nu exista orar stabilit!"],
                                noprog:["Nu exista programari!"],
                                test4:info4,
                                test5:info5,
                                test:info,
                                test2:info2,
                                test3:info3,
                                test6:info6,
                                test7:info7,
                                test_1:info_1,
                                test_2:info_2,
                                test_3:info_3,
                                test_4:info_4,
                                test_5:info_5,
                                test_6:info_6,
                                test_7:info_7
                            }) 
                        }
                        else if(rows==0 && contor == 1){
                            res.render('SecretaryScreen.ejs',{
                                noorar:["Nu exista orar stabilit!"],
                                test4:info4,
                                test5:info5,
                                test:info,
                                test2:info2,
                                test3:info3,
                                test6:info6,
                                test7:info7,
                                test_1:info_1,
                                test_2:info_2,
                                test_3:info_3,
                                test_4:info_4,
                                test_5:info_5,
                                test_6:info_6,
                                test_7:info_7
                            }) 
                        }
                        else if(rows != 0 && contor==0){
                            res.render('SecretaryScreen.ejs',{
                                noprog:["Nu exista programari!"],
                                test4:info4,
                                test5:info5,
                                test:info,
                                test2:info2,
                                test3:info3,
                                test6:info6,
                                test7:info7,
                                test_1:info_1,
                                test_2:info_2,
                                test_3:info_3,
                                test_4:info_4,
                                test_5:info_5,
                                test_6:info_6,
                                test_7:info_7
                            }) 
                            
                        }
                        else{
                            res.render('SecretaryScreen.ejs',{
                                test4:info4,
                                test5:info5,
                                test:info,
                                test2:info2,
                                test3:info3,
                                test6:info6,
                                test7:info7,
                                test_1:info_1,
                                test_2:info_2,
                                test_3:info_3,
                                test_4:info_4,
                                test_5:info_5,
                                test_6:info_6,
                                test_7:info_7
                            }) 
                        }
                        
                    })
                })
                }
                else if(result.type === 'pacient')
                {
                    var arr=[]

                    dbConnection.execute('SELECT consultatie_medic.nume, consultatie_medic.prenume, consultatie_medic.varsta, consultatie_medic.gender, consultatie_medic.CI, consultatie_medic.CNP, consultatie_medic.tara, consultatie_medic.judet, consultatie_medic.localitate, consultatie_medic.adresa, consultatie_medic.mediu, consultatie_medic.telefon, consultatie_medic.catProf, consultatie_medic.ocupatie, consultatie_medic.medFamilie, consultatie_medic.telefonMed, consultatie_medic.examinare, consultatie_medic.bilet_trimitere, consultatie_medic.radiologie, consultatie_medic.laborator, consultatie_medic.spital, consultatie_medic.other, consultatie_medic.scrMedicala, consultatie_medic.medicamente, consultatie_medic.total FROM consultatie_medic INNER JOIN login ON login.nume=consultatie_medic.nume AND login.prenume=consultatie_medic.prenume WHERE login.id=?',[req.session.userID]).then(([rows])=>{
                        if(rows.length == 0)
                        {
                            res.render('PatientScreen.ejs',{
                                medrez:["Nu aveti inca rezultate!"]
                            })
                        }
                        else
                        {
                            rows.map((result)=>{
                                
                                arr.push("Nume: "+result.nume)
                                arr.push("Prenume: "+result.prenume)
                                arr.push("Varsta: "+JSON.stringify(result.varsta))
                                arr.push("Sexul: "+result.gender)
                                arr.push("Nr card identitate: "+result.CI)
                                arr.push("CNP: "+result.CNP)
                                arr.push("Tara: "+result.tara)
                                arr.push("Judet: "+result.judet)
                                arr.push("Localitate: "+result.localitate)
                                arr.push("Adresa: "+result.adresa)
                                arr.push("Mediu: "+result.mediu)
                                arr.push("Telefon: "+JSON.stringify(result.telefon))
                                arr.push("Categorie profesionala: "+result.catProf)
                                arr.push("Ocupatie: "+result.ocupatie)
                                arr.push("Medic de familie: "+result.medFamilie)
                                arr.push("Telefon Medic de familie: "+JSON.stringify(result.telefonMed))
                                arr.push("Examinare: "+result.examinare)

                                if(JSON.stringify(Object.values(result.bilet_trimitere)) =='[1]')
                                {
                                    if(JSON.stringify(Object.values(result.radiologie)) =='[1]')
                                    {
                                        arr.push('Aveti trimitere catre radiologie!')
                                    } 
                                    if(JSON.stringify(Object.values(result.laborator)) =='[1]')
                                    {
                                        arr.push('Aveti trimitere catre laborator!')
                                    }
                                    if(JSON.stringify(Object.values(result.spital)) =='[1]')
                                    {
                                        arr.push('Aveti trimitere catre spital!')
                                    }
                                    if(JSON.stringify(Object.values(result.other)) =='[1]')
                                    {
                                        arr.push('Alte trimiteri.')
                                    }
                                }
                                if(JSON.stringify(Object.values(result.scrMedicala))=='[1]')
                                {
                                    arr.push("Medicamente: "+result.medicamente)
                                }
                                arr.push('Total costuri: '+JSON.stringify(result.total))
                                res.render('PatientScreen.ejs',{
                                    medrez:arr
                                })
                            })
                        }   
                    })
                }  
            }) 
        })
    }
})

// ###################################################################################################################################################

// ###############################################################     ROOT/HOME     #################################################################

// functia root/home
app.get('/',(req,res) => {
    if(!req.session.userID)
    {
        dbConnection.execute('SELECT * FROM tarife').then(([rows])=>{
            var consult = rows.map(information=>{
                return information.consultatie;
            })
            var intervent = rows.map(information2=>{
                return information2.interventie
            })
            
            res.render('HomeScreen.ejs',{
                consult:consult,
                interventie:intervent
            })
        })
        
    }
    else
    {
        res.redirect('/cont')             
    }   
})

// ###################################################################################################################################################

app.use(function(req, res, next){
    res.status(404);
    if (req.accepts('html')) {
      res.render('Error.ejs');
      return;
    }
})

// NU SE POT PUNE MAI MULTE GET-URI DUPA APP.USE DE AICI /\/\/\/\

// ###############################################################     LISTENING PORT     ############################################################

// portul pe care asculta
app.listen(4000, ()=>{
    console.log('Ascult pe portul 4000...')
});

// ###################################################################################################################################################