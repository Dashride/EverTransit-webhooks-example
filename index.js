require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const PORT = 3000;

const app = express();

app.use(express.json({
    verify: (req, _res, buf) => {
        req.rawBody = buf;
    },
}));

const isAuthorized = (req, res, next) => {
    const expectedSig = req.header('Webhook-Signature');
    const hash = crypto.createHmac('sha256', process.env.SECRET)
        .update(req.rawBody)
        .digest('base64');

    const actualSig = `sha256=${hash}`;
    if(crypto.timingSafeEqual(Buffer.from(actualSig), Buffer.from(expectedSig))){
        return next();
    }

    return res.sendStatus(401);
}

app.post('/webhook', isAuthorized, (req, res) => {
    const body = req.body;
    console.log(body);
    return res.sendStatus(200);
});

app.listen(PORT, () => {
    console.log(`Listening at port ${PORT}`);
});
