const sendToken =(user, StatusCode, res) => {


    //creating JWT Token//
    const token =user.getJWtToken();

    
    
    
    //sending response with token and user data//
    res.status(StatusCode)
    .json({
        success: true,
        token,
        user



    }).then
    
    
    
}
module.exports = sendToken;
