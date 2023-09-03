import std.algorithm.searching;
import std.conv;
import std.digest;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;
import std.typecons;

import vibe.db.mongo.mongo : connectMongoDB, MongoClient, MongoCollection;
import vibe.data.bson;

import dauth : makeHash, toPassword, parseHash;

struct DBConnection
{
    MongoClient client; 
    MongoCollection users, files, urls;
    enum UserRet
    {
        OK,
        ERR_NULL_PASS,
        ERR_USER_EXISTS,
        ERR_INVALID_EMAIL,
        ERR_WRONG_USER,
        ERR_WRONG_PASS,
        NOT_IMPLEMENTED
    }
    
    this(string dbUser, string dbPassword, string dbAddr, string dbPort, string dbName)
    {
	client = connectMongoDB("mongodb://" ~ dbUser ~ ":" ~ dbPassword ~ "@" ~ dbAddr ~ ":" ~ dbPort ~ "/");
	users = client.getCollection(dbName ~ ".users");	
	files = client.getCollection(dbName ~ ".files");
	urls = client.getCollection(dbName ~ ".urls");
    }

    UserRet addUser(string email, string username, string password, string name = "", string desc = "")
    {
	auto oneresult = users.findOne(["_id": email]);
        if (oneresult != Bson(null)) {
                return UserRet.ERR_USER_EXISTS;
        }

	string email1 = email;
	auto split = findSplit(email1, "@");
	if (split[0].empty || split[1].empty || split[2].empty) {
		return UserRet.ERR_INVALID_EMAIL;
	}
	auto split_again = findSplit(split[2], ".");
	if (split_again[0].empty || split_again[1].empty || split_again[2].empty) {
                return UserRet.ERR_INVALID_EMAIL;
        }
	if (split_again[2].length < 2) {
		return UserRet.ERR_INVALID_EMAIL;
	}
	string pass = password;
	if (pass.empty) {
		return UserRet.ERR_NULL_PASS;
	}

	users.insert(["_id": email, "key1": username, "key2": password, "key3": name, "key4": desc]);
        return UserRet.OK;
    }

    UserRet authUser(string email, string password)
    {
	string email1 = email;
        auto split = findSplit(email1, "@");
        if (split[0].empty || split[1].empty || split[2].empty) {
                return UserRet.ERR_INVALID_EMAIL;
        }
        auto split_again = findSplit(split[2], ".");
        if (split_again[0].empty || split_again[1].empty || split_again[2].empty) {
                return UserRet.ERR_INVALID_EMAIL;
        }
        if (split_again[2].length < 2) {
                return UserRet.ERR_INVALID_EMAIL;
        }
        string pass = password;
        if (pass.empty) {
                return UserRet.ERR_NULL_PASS;
        }
	auto oneresult = users.findOne(["_id": email, "key2": password]);
        if (oneresult != Bson(null)) {
                return UserRet.OK;
        }

        return UserRet.ERR_WRONG_PASS;
    }

    UserRet deleteUser(string email)
    {
	auto oneresult = users.findOne(["_id": email]);
        if (oneresult != Bson(null)) {
                users.remove(["_id": email]);
		auto result = files.find(["key1": email]);
		if (!result.empty) {
			files.update(["key1": email], ["key1": "Deleted_User"]);
			
		}
		auto result1 = urls.find(["key1": email]);
                if (!result1.empty) {
			urls.update(["key1": email], ["key1": "Deleted_User"]);                       
                }
        }

        return UserRet.OK;
    }

    struct File
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        ubyte[] binData;
        string fileName;
        string digest;
        string securityLevel;
    }

    enum FileRet
    {
        OK,
        FILE_EXISTS,
        ERR_EMPTY_FILE,
        NOT_IMPLEMENTED
    }

    FileRet addFile(string userId, immutable ubyte[] binData, string fileName)
    {
	string bindata = cast(string)binData;
	if (bindata.length == 0) {
                return FileRet.ERR_EMPTY_FILE;
        }
	auto oneresult = files.findOne(["key1": userId, "key2" : bindata, "key3": fileName]);
        if (oneresult != Bson(null)) {
                return FileRet.FILE_EXISTS;
        }
	auto id = BsonObjectID.generate();
	auto string_id = to!string(id);
	ubyte[] binData1 = binData.dup; 
	auto digest = digest!SHA512(binData1).toHexString().to!string;
	string securityLevel = "";
	files.insert(["_id": string_id, "key1": userId, "key2": bindata, "key3": fileName, "key4": digest, "key5": securityLevel]);
	return FileRet.OK;
    }

    File[] getFiles(string userId)
    {
	File[] file;
	auto result = files.find(["key1": userId]);
	if (result.empty) {
		return file;
		}
	int contor = 0;
	foreach(r; result) {
		File file1;
		file1.userId = to!string(r["key1"]);
		file1.binData = cast(ubyte[])(to!string(r["key2"]));
		file1.fileName = to!string(r["key3"]);
		file1.digest = to!string(r["key4"]);
		file1.securityLevel = to!string(r["key5"]);
		file = file ~ file1;
	}
	return file;
    }

    Nullable!File getFile(string digest)
    in(!digest.empty)
    do
    {
	auto result = files.findOne(["key4": digest]);
	if (result == Bson(null)) {
		return Nullable!File();
	}
	File file;
	file.userId = to!string(result["key1"]);
	file.binData = cast(ubyte[])(to!string(result["key2"]));
	file.fileName = to!string(result["key3"]);
	file.digest = to!string(result["key4"]);
	file.securityLevel = to!string(result["key5"]);
        return Nullable!File(file);
    }

    void deleteFile(string digest)
    in(!digest.empty)
    do
    {	
	auto result = files.findOne(["key4": digest]);
	files.remove(["key4": digest]);
    }

    struct Url
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        string addr;
        string securityLevel;
        string[] aliases;
    }

    enum UrlRet
    {
        OK,
        URL_EXISTS,
        ERR_EMPTY_URL,
        NOT_IMPLEMENTED
    }

    UrlRet addUrl(string userId, string urlAddress)
    {
	if (urlAddress.length == 0) {
		return UrlRet.ERR_EMPTY_URL;
	}
	auto result = urls.findOne(["key1": userId, "key2": urlAddress]);
	if (result != Bson(null)) {
		return UrlRet.URL_EXISTS;
	}
	auto id = BsonObjectID.generate();
	string string_id = to!string(id);
	string securityLevel = "";
	urls.insert(["_id": string_id , "key1": userId, "key2": urlAddress, "key3": securityLevel]);
        return UrlRet.OK;
    }

    Url[] getUrls(string userId)
    {
	Url[] url;
        auto result = urls.find(["key1": userId]);
        if (result.empty) {
                return url;
        }
        int contor = 0;
        foreach(r; result) {
                Url url1;
                url1.userId = to!string(r["key1"]);
                url1.addr = to!string(r["key2"]);
                url1.securityLevel = to!string(r["key3"]);
                url = url ~ url1;
        }
        return url;

    }

    Nullable!Url getUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
	auto result = urls.findOne(["key2": urlAddress]);
        if (result == Bson(null)) {
                return Nullable!Url();
        }
        Url url;
        url.userId = to!string(result["key1"]);
        url.addr = to!string(result["key2"]);
        url.securityLevel = to!string(result["key3"]);
       
        return Nullable!Url(url);
    }

    void deleteUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
	auto result = urls.findOne(["key2": urlAddress]);
	if (result != Bson(null)) {
		urls.remove(["key2": urlAddress]);
	}
	
    }
}
