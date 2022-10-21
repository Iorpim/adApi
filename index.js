var jwt = require("jsonwebtoken");
var AWS = require("aws-sdk");
if(!fetch) {
    var fetch = require("node-fetch");
}

AWS.config.update({region: "us-east-2"});

var secret = "zd0tq1ad8rzb48e2xcqica6j7zct89";
var client_id = "8gej984rx3ypt104fl0gkncne8z6sn";
var api_url = "https://api.twitch.tv/helix/";

var ddb = new AWS.DynamoDB({apiVersion: "2012-08-10"});

var TableName = "messageAuthTable";

var JWT_SECRET = "very real and safe secret *taidaSip*";

async function broadcasterGet(broadcasterId) {
    var params = {
        TableName: TableName,
        Key: {
            "broadcaster_id": {N: broadcasterId}
        }
    };
    return new Promise((resolve, reject) => {
        ddb.getItem(params, function(err, data) {
            if(err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}

var url = "https://lbmncmnhpdmapppoicnokookjppcikpp.chromiumapp.org/?code=e3zxtjasp47d78mxl10ga7cqenb5yk&scope=&state=c3ab8aa609ea11e793ae92361f002671";

function parse(q) {
    return new Proxy(new URLSearchParams(q), {
        get: (s, p) => s.get(p),
    });
}

function getFetch(url, params) {
    return new Promise((resolve, reject) => {
        fetch(url, params).then(x => x.text()).then(y => resolve(y)).catch(e => reject(e));
    });
}

function createToken(user_id, username, broadcaster_id, scope, expiration="24h") {
    var token = {
        userid: user_id,
        scope: scope,
        target: broadcaster_id,
        username: username
    };
    return jwt.sign(token, JWT_SECRET, {expiresIn: expiration});
}

function createUserToken(user, broadcaster_id) {
    return createToken(user.id, user.login, broadcaster_id, ["read"]);
}

function createBroadcasterToken(user) {
    return createToken(user.id, user.login, user.id, ["read", "write"], "90d");
}

function checkToken(token) {
    return jwt.verify(token, JWT_SECRET);
}

function encodeTwitchAuthToken(token) {
    return JSON.stringify(token);
}

function decodeTwitchAuthToken(token) {
    return JSON.parse(token);
}

async function broadcasterUpdate(broadcaster) {
    var params = {
        TableName: TableName,
        Item: broadcaster
    };
    return new Promise((resolve, reject) => {
        ddb.putItem(params, function(err, data) {
            if(err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}

async function broadcasterCreate(user, token) {
    var broadcaster = {
        broadcaster_id: {N: user.id},
        //allowed_users: {NS: []},
        username: {S: user.display_name},
        mods_only: {BOOL: false},
        auto_allow_mods: {BOOL: false},
        twitch_auth_token: {S: encodeTwitchAuthToken(token)}
    };
    return broadcasterUpdate(broadcaster);
}

async function broadcasterLogin(twitch_token) {
    var r = await _API.getToken(twitch_token);
    var token = JSON.parse(r);
    var API = new _API(token);
    r = await API.testToken(broadcaster);
    if(!r) {
        r = JSON.parse(await API.user());
    }
    var user = r.data[0]
    r = await broadcasterGet(user.id);
    if(!("Item" in r)) {
        r = await broadcasterCreate(user, token);
    } else {
        console.log(token);
        console.log(r);
        var broadcaster = r["Item"];
        broadcaster.twitch_auth_token = {S: encodeTwitchAuthToken(token)};
        r = await broadcasterUpdate(broadcaster);
    }
    if(r) {
        r = await createBroadcasterToken(user);
        return {"status": "success", "auth_token": r, "username": user.login, "user_id": user.id};
    } else {
        return {"status": "error", "response": "Failed to login user"};
    }
}

async function userLogin(jwt, target) {
    var token = checkToken(jwt);
    var r = (await broadcasterGet(token.userid));
    if(!("Item" in r)) {
        throw new Error("User not found");
    }
    var user = r.Item;
    var API = new _API(decodeTwitchAuthToken(user.twitch_auth_token.S));
    await API.testToken();
    r = await API.users(target);
    var broadcaster = JSON.parse(r).data[0];
    r = createUserToken({id: token.userid}, broadcaster.id);
    return {"status": "success", "auth_token": r, "username": broadcaster.login, "user_id": broadcaster.id};
}

async function broadcasterRemove(broadcaster_id) {
    var params = {
        TableName: TableName,
        Key: {
            "broadcaster_id": {N: broadcaster_id}
        }
    };
    return new Promise((resolve, reject) => {
        ddb.deleteItem(params, function(err, data) {
            if(err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}

async function delete_broadcaster(jwt) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("write") < 0) {
        throw new Error("Unauthorized");
    }
    var r = await broadcasterRemove(jwt.target);
    return {"status": "success", "response": "User profile deleted"};
}

async function add_allowed_user(jwt, user) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("write") < 0) {
        throw new Error("Unauthorized");
    }
    var broadcaster = (await broadcasterGet(token.target)).Item;
    var twitch_token = decodeTwitchAuthToken(broadcaster.twitch_auth_token.S);
    var API = new _API(twitch_token);
    await API.testToken(broadcaster);
    var user = JSON.parse(await API.users(user)).data[0];
    console.log(user);
    var user_id = `${user.id}:${user.login}`;
    if(broadcaster.allowed_users && broadcaster.allowed_users.SS) {
        console.log("a");
        var i = broadcaster.allowed_users.SS.map(e => e.split(":")[0]).indexOf(user.id);
        console.log(i);
        if(i >= 0) {
            if(broadcaster.allowed_users.SS[i] == user_id) {
                console.log(user_id);
                throw new Error("Duplicate user found");
            } else {
                console.log("b");
                broadcaster.allowed_users.SS[i] = user_id;
            }
        }
        broadcaster.allowed_users.SS = broadcaster.allowed_users.SS.concat(user_id);
    } else {
        broadcaster.allowed_users = {"SS": [user_id]};
        console.log(broadcaster);
    }
    var r = await broadcasterUpdate(broadcaster);
    return {"status": "success", "response": `User ${user.login} was added to allowed users list`, "username": user.login};
}

async function remove_allowed_user(jwt, user) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("write") < 0) {
        throw new Error("Unauthorized");
    }
    var broadcaster = (await broadcasterGet(token.target)).Item;
    var twitch_token = decodeTwitchAuthToken(broadcaster.twitch_auth_token.S);
    var API = new _API(twitch_token);
    await API.testToken(broadcaster);
    var user = JSON.parse(await API.users(user)).data[0];
    var user_id = user.id;
    var i = (broadcaster.allowed_users && broadcaster.allowed_users.SS) ? broadcaster.allowed_users.SS.map(e => e.split(":")[0]).indexOf(user_id) : -1;
    if(i < 0) {
        throw new Error("User not allowed");
    }
    if(broadcaster.allowed_users.SS.length == 1) {
        delete broadcaster.allowed_users;
    } else {
        delete broadcaster.allowed_users.SS[i];
    }
    var r = await broadcasterUpdate(broadcaster)
    return {"status": "success", "response": `User ${user} was removed from the allowed users lists`, "username": user};
}

async function get_allowed_users(jwt) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("read") < 0) {
        throw new Error("Unauthorized");
    }
    var broadcaster = (await broadcasterGet(token.target)).Item;
    return {"status": "success", "response": (broadcaster.allowed_users && broadcaster.allowed_users.SS) ? broadcaster.allowed_users.SS.map(e => e.split(":")[1]) : []};
}

function getOption(event, property, broadcaster) {
    switch(event[property]) {
        case "true":
            return {BOOL: true};
        case "false":
            return {BOOL: false};
        case "":
            return broadcaster[property];
        default:
            throw new Error(`Invalid value "${event[property]}" for property ${property}`);
    };
}

async function edit_options(jwt, event) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("write") < 0) {
        throw new Error("Unauthorized");
    }
    var broadcaster = (await broadcasterGet(token.target)).Item;
    broadcaster["mods_only"] = getOption(event, "mods_only", broadcaster);
    broadcaster["auto_allow_mods"] = getOption(event, "auto_allow_mods", broadcaster);
    var r = await broadcasterUpdate(broadcaster);
    return {"status": "success", "response": {"mods_only": broadcaster["mods_only"].BOOL,"auto_allow_mods": broadcaster["auto_allow_mods"].BOOL}};
}

async function get_options(jwt) {
    var token = checkToken(jwt);
    if(token.scope.indexOf("read") < 0) {
        throw new Error("Unauthorized");
    }
    var broadcaster = (await broadcasterGet(token.target)).Item;
    return {"status": "success", "response": { "mods_only": broadcaster.mods_only.BOOL, "auto_allow_mods": broadcaster.auto_allow_mods.BOOL }};
}

/*function createUserIDToken(user) {
    return createToken(user.id, -1, [], "7d");
}*/

class _API {
    constructor(token){
        this.token = token;
    }


    static getToken(url) {
        var [r, a] = url.split("?");
        a = parse(a);
        return this._getToken(a.code, r);
    }

    static _getToken(code, r) {
        return getFetch("https://id.twitch.tv/oauth2/token", {
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": `client_id=${client_id}&client_secret=${secret}&code=${code}&grant_type=authorization_code&redirect_uri=${r}`,
            "method": "POST"
        });
    }

    async refreshToken() {
        var token = JSON.parse(await getFetch("https://id.twitch.tv/oauth2/token", {
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": `client_id=${client_id}&client_secret=${secret}&grant_type=refresh_token&refresh_token=${this.token.refresh_token}`,
            "method": "POST"
        }));
        if(token.status == 401) {
            console.error(token);
            throw new Error("Invalid broadcaster refresh_token.");
        }
        this.token = token;
        return this.token;
    }

    getHeaders() {
        return {
            "Authorization": `Bearer ${this.token.access_token}`,
            "Client-Id": client_id
        };
    }

    async getAPI(endpoint) {
        var r = await getFetch(api_url + endpoint, {
            "headers": this.getHeaders(),
        });
        if(JSON.parse(r).status == 401) {
            throw new Error("Unauthorized");
        }
        return r;
    }

    users(usernames = "", ids = "") {
        var endpoint = "users";
        var params = [];
        if(ids.length) {
            if(ids instanceof Array) {
                ids = ids.join(",");
            }
            params = params.concat(`id=${ids}`);
        }
        if(usernames.length) {
            if(usernames instanceof Array) {
                usernames = usernames.join(",");
            }
            params = params.concat(`login=${usernames}`);
        }
        if(params) {
            endpoint = `users?${params.join("&")}`;
        }
        return this.getAPI(endpoint);
    }

    user() {
        return this.getAPI("users");
    }

    moderators(broadcaster_id, userIds = [], first = 100, after = "") {
        var endpoint = `moderation/moderators?broadcaster_id=${broadcaster_id}&first=${first}`;
        if(userIds.length) {
            if("," in userIds) {
                userIds = userIds.split(",");
            }
            if(userIds instanceof Array) {
                userIds = userIds.join("&user_id=");
            }
            endpoint += `&user_id=${userIds}`;
        }
        return this.getAPI(endpoint);
    }

    async testToken(broadcaster) {
        try { return JSON.parse(await this.user()) } catch {
            var token = await this.refreshToken();
            broadcaster.twitch_auth_token.S = encodeTwitchAuthToken(token);
            await broadcasterUpdate(broadcaster);
            return false;
        }
    }
}

async function getUser(API) {
    var r = await API.user();
    console.log(r);
    var user = JSON.parse(r);
    if(user.status == 401) {
        r = await API.refreshToken();
        console.log(r);
        var token = JSON.parse(r);
        if(token.status == 401) {
            throw new Error();
        }
        r = await API.user();
        console.log(r);
        user = JSON.parse(r);
    }
    /*r = await API.moderators(user.data[0].id);
    console.log(r)*/
    return user;
}

exports.handler = async (event, context) => {
    // TODO implement
    console.log(JSON.stringify(event, null, 2));
    console.log(JSON.stringify(context, null, 2));
    /*const response = {
        statusCode: 200,
        body: JSON.stringify('Hello from Lambda!'),
    };*/
    var response = {"status": "error", "response": "undefined error"};
    try {
        switch(event["action"]) {
            case "login":
                response = await broadcasterLogin(event["token"]);
                break;
            case "delete":
                response = await delete_broadcaster(event["authorisation"]);
                break;
            case "addAllowedUser":
                response = await add_allowed_user(event["authorisation"], event["username"]);
                break;
            case "removeAllowedUser":
                response = await remove_allowed_user(event["authorisation"], event["username"]);
                break;
            case "getAllowedUsers":
                response = await get_allowed_users(event["authorisation"]);
                break;
            case "editOptions":
                response = await edit_options(event["authorisation"], event);
                break;
            case "getOptions":
                response = await get_options(event["authorisation"]);
                break;
            case "userLogin":
                response = await userLogin(event["authorisation"], event["broadcaster"]);
                break;
            case "main":
                response = await main(event);
                break;
            default:
                response = {"status": "error", "response": `Invalid action: ${event["action"]}`};
                break;
        }
    } catch(e) {
        console.error(e);
        throw e;
    }
    return response;//event["queryStringParameters"]["api-key"];//response;
};


async function main(event) {
    //console.log("aaaa");
    //var token = JSON.parse(`{"access_token":"0zp590ciql55jb8upwwalvb4ehheql","expires_in":14698,"refresh_token":"1jvjikabh96cl4vuaw9mvikghusjyebw43hic32pker647535e","scope":["moderation:read","user:read:email"],"token_type":"bearer"}`)
    //var token = JSON.parse(`{"access_token":"2i0o50mvdjvnn716ekgvksjy8n557r","expires_in":13515,"refresh_token":"f8ya3zqzoykrvkocwkfw7e8t33dsr3nuq0zwgzbbhzz9atrwt6","token_type":"bearer"}`);
    /*if(!token) {
        var r = await _API._getToken(url);
        console.log(r);
        var token = JSON.parse(r);
    }
    var API = new _API(token);
    var user = await getUser(API);
    var userToken = createUserToken(user.data[0], "aaaaaaaaaa");
    console.log(userToken);
    var broadcasterToken = createBroadcasterToken(user.data[0], token);
    console.log(broadcasterToken);*/
    //console.log(await broadcasterGet("36419555"));
    var token = checkToken(event["authorisation"]);
    var API = new _API(token.twitch_auth_token);
    var broadcaster = (await broadcasterGet(token.target)).Item;
    console.log(broadcaster);
    broadcaster.twitch_auth_token = {S: JSON.stringify(await API.refreshToken())};
    console.log(await broadcasterUpdate(broadcaster));
}

//main();