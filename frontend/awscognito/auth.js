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
function showSignedIn(session) {
    document.getElementById("statusNotAuth").style.display = 'none';
    document.getElementById("statusAuth").style.display = 'block';
    document.getElementById("signInButton").innerHTML = "Sign Out";
    document.getElementById("loader").style.display = "block";
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

// Initialize a cognito auth object.
async function initCognitoSDK() {
    const config = await getConfig();
    let auth = new AWSCognito.CognitoIdentityServiceProvider.CognitoAuth(config.authData);
    auth.userhandler = {
        onSuccess: function(result) {
            console.log("Cognito Sign in successful!");
            showSignedIn(result);
            let id_token = auth.signInUserSession.idToken.jwtToken;
            let cognitoParams = {
                IdentityPoolId: config.identityPool,
                Logins: {}
            };
            cognitoParams.Logins["cognito-idp."+config.region+".amazonaws.com/"+config.poolId] = id_token;
            AWS.config.credentials = new AWS.CognitoIdentityCredentials(cognitoParams);
            AWS.config.getCredentials(function(){
                let creds = {
                    "sessionId":AWS.config.credentials.accessKeyId,
                    "sessionKey":AWS.config.credentials.secretAccessKey,
                    "sessionToken":AWS.config.credentials.sessionToken
                }
                let credsEncoded = encodeURIComponent(JSON.stringify(creds));
                let uri = "https://signin.aws.amazon.com/federation?Action=getSigninToken&SessionDuration=43200&Session="+credsEncoded;
                $.ajax({
                    type : 'POST',
                    url : config.endpoint,
                    headers : {
                        Authorization : id_token
                    },
                    data : uri,
                    success : function(response) {
                        let quickSightSSO = "https://signin.aws.amazon.com/federation?Action=login&Issuer="+thisUrlEncoded+"&Destination="+quicksightUrlEncoded+"&SigninToken="+response.SigninToken
                        console.log("Federated Sign In Token: "+response.SigninToken);
                        console.log("AWS Console Sign In URL: "+quickSightSSO);
                        window.location = quickSightSSO;
                        document.getElementById("consoleLink").innerHTML = "<a href='"+quickSightSSO+"'>"+"https://quicksight.aws.amazon.com"+"</a>";
                        document.getElementById("loader").style.display = "none";
                        document.getElementById("instructions").style.display = 'block';
                    },
                    error : function(xhr, status, error) {
                        var err = eval(xhr.responseText);
                        console.log(JSON.stringify(xhr)); 
                        if(xhr.status == "0"){
                            document.getElementById("statusAuth").innerHTML = "<h5>Token Expired or Invalid! Signing Out...</h5>"
                            auth.signOut();
                        }                  
                    }
                });
                
            });
        },
        onFailure: function(err) {
            console.log("Error!" + err);
            document.getElementById("statusAuth").innerHTML = "<h5>Token Expired or Invalid! Signing Out...</h5>"
            auth.signOut();
        }
    };
    // The default response_type is "token", uncomment the next line will make it be "code".
    // auth.useCodeGrantFlow();
    return auth;
}

window.onload = async () => {
    document.getElementById("statusNotAuth").style.display = 'block';
    document.getElementById("statusAuth").style.display = 'none';
    document.getElementById("instructions").style.display = 'none';
    // Initiatlize CognitoAuth object
    const auth = await initCognitoSDK();
    document.getElementById("signInButton").addEventListener("click", function() {
        userButton(auth);
    });
    var curUrl = window.location.href;
    auth.parseCognitoWebResponse(curUrl);
}
