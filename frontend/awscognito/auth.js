const fetchAuthConfig = async () => {
    const response = await fetch("/auth_config.json");
    return response.json();
}

let _config = null;
const getConfig = async () => {
    if (!_config) {
        _config = await fetchAuthConfig();
    }

    return _config;
}

// Operations when signed in.
function updateUI(isAuth) {
    if (isAuth) {
        document.getElementById("statusNotAuth").style.display = 'none';
        document.getElementById("statusAuth").style.display = 'block';
        document.getElementById("signInButton").innerHTML = 'Sign Out';
        document.getElementById("loader").style.display = "block";
        document.getElementById("ping-result").style.display = 'block';
        document.getElementById("ping-button").style.display = 'block';
    } else {
        document.getElementById("statusNotAuth").style.display = 'block';
        document.getElementById("statusAuth").style.display = 'none';
        document.getElementById("signInButton").innerHTML = 'Sign In';
        document.getElementById("loader").style.display = 'none';
        document.getElementById("ping-result").style.display = 'none';
        document.getElementById("ping-button").style.display = 'none';
    }
}

// Perform user operations.
function userButton(auth) {
    var state = document.getElementById('signInButton').innerHTML;
    var statestr = state.toString();
    if (statestr.includes("Sign Out")) {
        document.getElementById("signInButton").innerHTML = "Sign In";
        auth.signOut();
        showSignedOut();
    } else {
        auth.getSession();
    }
}

async function callAPI(auth) {
    try {
        const config = await getConfig();
        const token = auth.signInUserSession.idToken.jwtToken;

        const response = await fetch(`${config.endpoint}/ping`, {
            headers: {
            Authorization: `Bearer ${token}`
            }
        });

        const responseData = await response.json();
        const responseElement = document.getElementById("api-call-result");
        responseElement.innerText = JSON.stringify(responseData, {}, 2);
        document.querySelectorAll("pre code").forEach(hljs.highlightBlock);
        document.getElementById("ping-result").style.display = 'block';
    } catch (e) {
        console.error(e);
    }
}

// Initialize a cognito auth object.
async function initCognitoSDK() {
    const config = await getConfig();
    let auth = new AWSCognito.CognitoIdentityServiceProvider.CognitoAuth(config.authData);
    auth.userhandler = {
        onSuccess: function(result) {
            console.log("Cognito Sign in successful!");
            updateUI(true);
        },
        onFailure: function(err) {
            console.log("Error!" + err);
            document.getElementById("statusAuth").innerHTML = "<h5>Token Expired or Invalid! Signing Out...</h5>"
            auth.signOut();
            updateUI(false);
        }
    };
    // The default response_type is "token", uncomment the next line will make it be "code".
    // auth.useCodeGrantFlow();
    return auth;
}

window.onload = async () => {
    updateUI(false);
    // Initiatlize CognitoAuth object
    const auth = await initCognitoSDK();
    document.getElementById("signInButton").addEventListener("click", function() {
        userButton(auth);
    });
    document.getElementById("pingButton").addEventListener("click", function() {
        callAPI(auth);
    });
    var curUrl = window.location.href;
    auth.parseCognitoWebResponse(curUrl);
}
