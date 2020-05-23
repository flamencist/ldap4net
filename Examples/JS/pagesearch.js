var ldap = require("ldapjs");

var client = ldap.createClient({
    url:"",
    strictDN:""
});

client.bind("","",function(err){
    client.search("",{filter:"(objectclass=*)", scope:"sub", paged:{
        pageSize: 3,
        pagePause:false
    }}, function(err, res){

        console.log(res);
        res.on('searchEntry', function(entry) {
            // Submit incoming objects to queue
            console.log("searchEntry", entry.messageID, entry.objectName)
        });
        res.on('page', function(result, cb) {
            // Allow the queue to flush before fetching next page
            console.log("page", result.messageID,result.controls[0]._value.cookie.length, result.controls[0]._value);
        });
        res.on('error', function(resErr) {
            console.log("error", resErr);
        });
        res.on('end', function(result) {
            console.log('done', result);
        });
    });
});

