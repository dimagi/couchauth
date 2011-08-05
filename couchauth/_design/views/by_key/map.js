function (doc) {
    var i;
    if (doc.hasOwnProperty('password') && /\$.*\$/.exec(doc.password)) {
        emit(doc._id, null);
        for (i = 0; i < doc.emails.length; i += 1) {
            emit(doc.emails[i], null);
        }
    }
}