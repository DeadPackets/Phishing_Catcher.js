const WebSocket = require('ws');
const chalk = require('chalk');
const levenshtein = require('fast-levenshtein');
const calc = require('binary-shannon-entropy');

//Vars
const keywords = {
    'login': 25,
    'log-in': 25,
    'sign-in': 25,
    'signin': 25,
    'account': 25,
    'verification': 25,
    'verify': 25,
    'webscr': 25,
    'password': 25,
    'credential': 25,
    'support': 25,
    'activity': 25,
    'security': 25,
    'update': 25,
    'authentication': 25,
    'authenticate': 25,
    'authorize': 25,
    'wallet': 25,
    'alert': 25,
    'purchase': 25,
    'transaction': 25,
    'recover': 25,
    'unlock': 25,
    'confirm': 20,
    'live': 15,
    'office': 15,
    'service': 15,
    'manage': 15,
    'invoice': 15,
    'secure': 10,
    'customer': 10,
    'client': 10,
    'bill': 10,
    'online': 10,
    'safe': 10,
    'form': 10,
    'appleid': 70,
    'icloud': 60,
    'iforgot': 60,
    'itunes': 50,
    'apple': 30,
    'outlook': 60,
    'office365': 50,
    'microsoft': 60,
    'windows': 30,
    'protonmail': 70,
    'tutanota': 60,
    'hotmail': 60,
    'gmail': 70,
    'google': 70,
    'outlook': 60,
    'yahoo': 60,
    'google': 60,
    'yandex': 60,
    'twitter': 60,
    'facebook': 60,
    'tumblr': 60,
    'reddit': 60,
    'youtube': 40,
    'linkedin': 60,
    'instagram': 60,
    'flickr': 60,
    'whatsapp': 60,
    'localbitcoin': 70,
    'poloniex': 60,
    'coinhive': 70,
    'bithumb': 60,
    'kraken': 50,
    'bitstamp': 60,
    'bittrex': 60,
    'blockchain': 70,
    'bitflyer': 60,
    'coinbase': 60,
    'hitbtc': 60,
    'lakebtc': 60,
    'bitfinex': 60,
    'bitconnect': 60,
    'coinsbank': 60,
    'paypal': 70,
    'moneygram': 60,
    'westernunion': 60,
    'bankofamerica': 60,
    'wellsfargo': 60,
    'citigroup': 60,
    'santander': 60,
    'morganstanley': 60,
    'barclays': 50,
    'hsbc': 50,
    'scottrade': 60,
    'ameritrade': 60,
    'merilledge': 60,
    'bank': 15,
    'amazon': 60,
    'overstock': 60,
    'alibaba': 60,
    'aliexpress': 60,
    'leboncoin': 70,
    'netflix': 70,
    'skype': 60,
    'github': 60,
    'cgi-bin': 50,
    '.com-': 20,
    '-com.': 20,
    '.net-': 20,
    '.org-': 20,
    '.com-': 20,
    '.net.': 20,
    '.org.': 20,
    '.com.': 20,
    '.gov-': 30,
    '.gov.': 30,
    '.gouv-': 40,
    '-gouv-': 40,
    '.gouv.': 40,
}

const keysArray = Object.keys(keywords)

const suspicious_tlds = [
    '.ga',
    '.gq',
    '.ml',
    '.cf',
    '.tk',
    '.xyz',
    '.pw',
    '.cc',
    '.club',
    '.work',
    '.top',
    '.support',
    '.bank',
    '.info',
    '.study',
    '.party',
    '.click',
    '.country',
    '.stream',
    '.gdn',
    '.mom',
    '.xin',
    '.kim',
    '.men',
    '.loan',
    '.download',
    '.racing',
    '.online',
    '.center',
    '.ren',
    '.gb',
    '.win',
    '.review',
    '.vip',
    '.party',
    '.tech',
    '.science',
    '.business'
]

const origKeys = ['com', 'net', 'org'];

const ws = new WebSocket('wss://certstream.calidog.io', {
    perMessageDeflate: false
})

ws.on('open', function () {
    console.log(chalk.green('Connected to CertStream!'))
})

ws.on('message', function (data) {
    let parsed = JSON.parse(data);

    if (parsed.message_type == 'certificate_update') {

        let certIssuer = parsed.data.chain[0].subject.O
        parsed.data.leaf_cert.all_domains.forEach(function (item, i) {

            let score = 0;

            if (certIssuer.toLowerCase() == "let's encrypt") {
                score += 10
            }

            suspicious_tlds.forEach(function (tld, i) {
                if (item.endsWith(tld)) {
                    score += 20;
                }
            })

            let words_in_domain = item.split(/\W+/)

            keysArray.forEach(function (key, i) {
                if (item.includes(key)) {
                    score += keywords[key]
                }

                if (keywords[key] >= 60) {
                    words_in_domain.forEach(function (word, i) {
                        if (word !== 'mail' && word !== 'email' && word !== 'cloud' && (levenshtein.get(word, key) == 1)) {
                            score += 70
                        }
                    })
                }
            })

            origKeys.forEach(function (key, i) {
                if (item.includes(key)) {
                    score += 10
                }
            })

            if (item.includes('com') || item.includes('net') || item.includes('org')) {
                score += 10
            }

            if ((item.indexOf('xn--') < 0) && (item.split('-').length - 1) >= 3) {
                score += ((item.split('-').length - 1) * 3)
            }

            if ((item.split('.').length - 1) >= 3) {
                score += ((item.split('.').length - 1) * 3)
            }

            score += Math.round(calc(Buffer(item) * 5))

            if (score >= 100) {
                console.log(chalk.red.bold(`[!!] Suspicious: ${item} (${score})`))
            } else if (score >= 90) {
                console.log(chalk.red(`[!] Suspicious: ${item} (${score})`))
            } else if (score >= 80) {
                console.log(chalk.yellow.bold(`[!!] Potential: ${item} (${score})`))
            } else if (score >= 65) {
                console.log(chalk.yellow(`[!] Potential: ${item} (${score})`))
            } else if (process.env.DEBUG == "true") {
                console.log('Debug!', item, score)
            }

        })
    } else {
        if (process.env.DEBUG == "true") {
            console.log(chalk.blue('Heartbeat recieved!'))
        }
    }
})