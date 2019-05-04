import os
import sqlite3
import json
import requests
import argparse
from pprint import pprint
import feedparser
from newspaper import Article
import yara
import redis;

conn = None

def isMatch(rule, target_path):
    #rule = compiled yara rules
    m = rule.match(target_path)
    if m:
        return True
    else:
        return False


def compileRules(rule_path):
    ruleSet=[]
    files = os.walk(rule_path)
    for root, sub, files in os.walk(rule_path):
        #print("Compiling Rules")
        for file in files:
            #print("\t"+os.path.join(root,file))
            rule = yara.compile(os.path.join(root,file))
            ruleSet.append(rule)
    return ruleSet


def scanTargetDirectory(target_path, ruleSet ):
    for root, sub, files in os.walk(target_path):
        for file in files: #check each file for rules
            print("\t"+os.path.join(root,file))
            for rule in ruleSet:
                if(isMatch(rule,os.path.join(root,file))):
                    matches = rule.match(os.path.join(root,file))
                    if(matches):
                        for match in matches:
                            print("\t\tYARA MATCH: "+ os.path.join(root,file)+"\t"+match.rule)


def scanTargetLink(target_path, ruleSet ):
    article = Article(target_path)
    article.download()
    article.parse()

    with open("tmp", "w") as f:
        f.write(article.text)
    
    results = [] 
    for rule in ruleSet:
        matches = rule.match("tmp")
        if(matches):

            print("URL: "+ target_path)
            for match in matches:
                results.append(match)
                print("Match: "+ str(match))

    # remove tmp file
    os.remove("tmp")
    return results

def main():
    art= '''
      \:.     .:/
       \:::::::/ 
        \:::::/ 
         \:::/   
          \:/    
           .  
          .:.   
    '''
    print(art+"Welcome to Funnel\n")

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-u", "--url", help="scan one url instead of using sources list", action="store_true")
    parser.add_argument("rule_path", help="path to file or directory of rules used on list of feeds")
    parser.add_argument("target_path", help="path to sources list or url")

    args = parser.parse_args()

    idF = 0

    redis_db = redis.StrictRedis()
    redis_db.flushall()

    if(args.verbose): print("Loading rules")

    ruleset = compileRules(args.rule_path)


    if(args.url):
        if(args.verbose): print("Scanning URL...")
        scanTargetLink(args.target_path,ruleset)
    else:
        if(args.verbose): print("Reading from Sources list...")
        
        with open(args.target_path, "r") as f:
            sources = json.load(f)
            for source in sources["sources-rss"]:
                if(args.verbose): print("Reading Feed: "+source["title"])

                feed = feedparser.parse(source["url"])

                for post in feed.entries:
                    if (args.verbose): print(post.link)
                    if("http" in post.link):
                        try:
                            matches = scanTargetLink(post.link, ruleset)
                        except Exception as e:
                            print(e)

                        if(matches):
                            keyPart = str(idF) + ':' + post.link
                            redis_db.sadd(keyPart, post.title)
                            idF += 1
                            for match in matches:
                                redis_db.sadd(keyPart, str(match))


    print ("-----------------------------------Result-------------------------------------------------")
    for key in redis_db.keys():
        print("URL: " + str(key)[2:])
        elements = redis_db.sscan(key)
        print("Match: " + str(elements[1][0]))
        print("Title: " + str(elements[1][1]))

if __name__ == "__main__":
    main()
