#'
#' IANA root files: https://www.iana.org/domains/root/files
#'



#' RIPE: ftp://ftp.ripe.net/ripe/dbase/split/
#' APNIC: https://ftp.apnic.net/apnic/whois/
#' ARIN: https://ftp.arin.net/pub/rr/
#' AFRINIC: ftp://ftp.afrinic.net/pub/dbase/
#' LACNIC: ?? http://www.lacnic.net/en/web/lacnic/manual-8
#' Others: http://www.irr.net/docs/list.html

validRIRNames <- function() {
  vnames <- c("ripe",
              "apnic",
              "arin",
              "afrinic",
              "lacnic",
              "others")
  return(vnames)
}

validDataNames <- function() {
  vnames <- c("as-block",
              "as-set",
              "aut-num",
              "filter-set",
              "domain",
              "inet-rtr",
              "inet6num",
              "inetnum",
              "irt",
              "key-cert",
              "mntner",
              "organisation",
              "peering-set",
              "person",
              "role",
              "route-set",
              "route",
              "route6",
              "rtr-set")
  return(vnames)
}

updateRawData <- function(db = "all") {
  downloadRawData <- function(db) {
    if ("ripe" %in% db) {
      for (vn in validDataNames()) {
        download.file(url = paste("ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.", vn, ".gz", sep = ""),
                      destfile = paste("./dataraw/ripe.", vn, ".db.gz", sep = ""))
      }
    }
    if ("apnic" %in% db) {
      for (vn in validDataNames()[!validDataNames() %in% c("person")]) {
        download.file(url = paste("https://ftp.apnic.net/apnic/whois/apnic.db.", vn, ".gz", sep = ""),
                      destfile = paste("./dataraw/apnic.", vn, ".db.gz", sep = ""))
      }
    }
    if ("arin" %in% db) {
      download.file(url = "https://ftp.arin.net/pub/rr/arin.db", destfile = "./dataraw/arin.db")
    }
    if ("afrinic" %in% db) {
      download.file(url = "ftp://ftp.afrinic.net/pub/dbase/afrinic.db.gz", destfile = "./dataraw/afrinic.db.gz")
    }
    if ("lacnic" %in% db) {
      # TODO
    }
    if ("others" %in% db) {
      # TODO
    }
  }
  db <- tolower(db)
  if ((db %in% validRIRNames()) || db == "all") {
    if ((length(db) == 1) && (db != "all")) {
      # download db
      downloadRawData(db)
    } else if ((length(db) > 1) ||
               ((length(db) == 1) && (db == "all"))) {
      if ((length(db) == 1) && (db == "all")) {
        db <- validRIRNames()
      }
      # for each db: download
      for (vn in db) {
        downloadRawData(vn)
      }
    } else {
      print(paste("Please, use valid names: all",validRIRNames(), collapse = ", "))
      return()
    }
  } else {
    print(paste("Please, use valid names: 'all' or '",paste(validRIRNames(), collapse = "', '"), "'.", sep = ""))
    return()
  }
  # unzip
  sapply(list.files(path = "./dataraw/", pattern = "*.gz", full.names = T), R.utils::gunzip)
}

getWhois <- function(db = "all") {
#  updateRawData(db)
  i <- 1
  whois.db <- list()
  for (rawfile in list.files(path = "./dataraw/", pattern = "*.db", full.names = T)) {
    whois.db[[i]] <- processWhois(rawfile)
    i <- i + 1
    save(whois.db, file = "./dataraw/whois.db.rda")
  }
  return(whois.db)
}


#' Whois Parser help
#' RIPE Database Reference Manual: ftp://ftp.ripe.net/ripe/docs/ripe-252.txt
#' APNIC Guide: https://www.apnic.net/manage-ip/using-whois/guide/
processWhois <-  function(filepath) {
  i <- 1
  # Init local variables
  newobject <- TRUE
  current.obj <- ""
  current.obj.type <- ""
  current.var <- ""
  current.var.type <- ""

  # Standard words (except nonstdwords)
  stopwords <- c("as-block", "as-set", "aut-num", "domain", "filter-set","inet6num",
                 "inetnum", "inet-rtr", "irt", "key-cert","limerick", "mntner", "peering-set",
                 "person", "role", "route", "route6", "route-set", "rtr-set")
  stopwords <- stringr::str_replace(stopwords,"-",".")
  validwords <- c("descr","country","members","mbrs.by.ref","remarks","tech.c","admin.c","notify",
                  "mnt.lower","mnt.by","changed","source","as.set","as.name","member.of","import",
                  "export","default","cross.mnt","cross.nfy","mnt.routes","mnt.irt","aut.num",
                  "netname","geoloc","language","rev.srv","status","inet6num","inetnum","alias",
                  "local.as","ifaddr","peer","mp.peer","inet.rtr","method","owner","fingerpr",
                  "certif","key.cert","upd.to","mnt.nfy","auth","abuse.mailbox","referral.by",
                  "mntner","origin","holes","inject","aggr.mtd","aggr.bndry","export.comps",
                  "components","route","org","route6","mp.members","route.set","created",
                  "last.modified")
  nonstdwords <- c("type")
  validwords <- unique(c(stopwords,validwords, nonstdwords))

  # New whois data base
  whois.db <- list()
  whois.db <- lapply(stringr::str_replace(stopwords,"-","."), function(x) list())
  names(whois.db) <- stopwords

  # Parse raw file
  con = file(filepath, "r")
  while (TRUE) {
    # XXX: Used to detect non-standard objects
    # if (i %in% c(10,535)) {
    #   dummy <- NA
    # }

    line = readLines(con, n = 1)

    # Skip special lines need special treatment

    ## Last line: save last object and break
    if (length(line) == 0) {
      whois.db[[current.obj.type]][[length(whois.db[[current.obj.type]]) + 1]] <- current.obj
      break
    }
    ## Empty line, usually between two objects
    if ((length(line == 1)) && (nchar(line) == 0)) {
      next
    }
    ## Skip comments
    if (stringr::str_sub(line, 1, 1) == "#") {
      next
    }

    # New line pre-process
    if (stringr::str_detect(line, ":")) {
      # Maybe it's a variable, let's split just in case
      line <- c(stringr::str_replace(stringr::str_sub(line, 1, stringr::str_locate(line, ":")[1] - 1),"-","."),
                stringr::str_trim(stringr::str_sub(line, stringr::str_locate(line, ":")[1] + 1, nchar(line))))
      # if line[1] is in current.obj & not stopword -> paste-text
      # if line[1] is in current.obj & stopword -> split
      # if line[1] isn't in current.obj & not stopword -> paste-all
      # if line[1] isn't in current.obj & stopword -> split
      if (line[1] %in% names(current.obj)) {
        if (line[1] %in% stopwords) {
          # Variable for new object, same objtype
          newobject <- TRUE
        } else {
          # variable for current object
          newobject <- FALSE
        }
      } else {
        if (line[1] %in% stopwords) {
          # Variable for new object, different objtype
          newobject <- TRUE
        } else {
          # non-standard or more info with char ":" inside
          if (line[1] %in% validwords) {
            # Non-standard attribute for this object
            print(paste("Element:", i))
            print("WARNING: Non-standard attribute!")
            print(current.obj)
          }
          # More info for current variable
          line <- stringr::str_trim(line[2])
          newobject <- FALSE
        }
      }
    } else {
      # It's more text for current variable
      line <- stringr::str_trim(line)
      newobject <- FALSE
    }

    switch(as.character(length(line)),
            "1" = {
              # More info for current variable: add line.txt to current.var
              if (line != "") {
                current.var[2] <- paste(current.var[2],
                                        line, sep = "\n")
                current.obj[[current.var.type]] <- current.var[2]
              }
            },
            "2" = {
              # New variable
              current.var[1] <- line[1]
              current.var[2] <- line[2]
              current.var.type <- current.var[1]
              # if (current.var.type %in% stopwords) {
              if (newobject) {
              # Save current.obj in whois.db
                whois.db[[current.obj.type]][[length(whois.db[[current.obj.type]]) + 1]] <- current.obj
                # Initiate current object
                current.obj.type <- current.var.type
                current.obj <- newWhoisObject(current.var)
                # XXX: Used to detect non-standard objects
                # print(paste("Element:", i))
                i <- i + 1
              } else {
                # New variable: add current.var to current.obj
                current.obj[[current.var.type]] <- current.var[2]
              }
            },
            {
              # XXX: Used to detect non-standard objects
              print("default case")
            }
           )
  }
  close(con)

  # Tidy data
  whois.db <- lapply(stopwords, function(x) x = as.data.frame(dplyr::bind_rows(whois.db[[x]])))
  names(whois.db) <- stopwords

  return(whois.db)
}

newWhoisObject <- function(cvar = "") {
  wo <- data.frame()
  switch(cvar[1],
         "as.block" = {
           wo <- data.frame(objtype = cvar[1],
                            "as.block" = cvar[2],
                            type = "",
                            descr = "",
                            country = "",
                            remarks = "",
                            org = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.lower = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "as.set" = {
           wo <- data.frame(objtype = cvar[1],
                            "as.set" = cvar[2],
                            descr = "",
                            org = "",
                            country = "",
                            members = "",
                            mbrs.by.ref = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            upd.to = "",
                            notify = "",
                            mnt.lower = "",
                            mnt.by = "",
                            mnt.nfy = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "aut.num" = {
           wo <- data.frame(objtype = cvar[1],
                            "aut.num" = cvar[2],
                            as.name = "",
                            descr = "",
                            status = "",
                            country = "",
                            member.of = "",
                            import = "",
                            export = "",
                            default = "",
                            remarks = "",
                            org = "",
                            admin.c = "",
                            tech.c = "",
                            upd.to = "",
                            cross.mnt = "",
                            cross.nfy = "",
                            notify = "",
                            mnt.lower = "",
                            mnt.routes = "",
                            mnt.by = "",
                            mnt.irt = "",
                            mnt.nfy = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "domain" = {
           wo <- data.frame(objtype = cvar[1],
                            "domain" = cvar[2],
                            descr = "",
                            org = "",
                            country = "",
                            admin.c = "",
                            tech.c = "",
                            zone.c = "",
                            nserver = "",
                            sub.dom = "",
                            dom.net = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            refer = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "filter.set" = {
           wo <- data.frame(objtype = cvar[1],
                            "filter.set" = cvar[2],
                            descr = "",
                            filter = "",
                            org = "",
                            mp.filter = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            created = "",
                            last.modified = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "inet6num" = {
           wo <- data.frame(objtype = cvar[1],
                            "inet6num" = cvar[2],
                            netname = "",
                            descr = "",
                            country = "",
                            org = "",
                            geoloc = "",
                            language = "",
                            admin.c = "",
                            tech.c = "",
                            rev.srv = "",
                            status = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            mnt.irt = "",
                            mnt.routes = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "inetnum" = {
           wo <- data.frame(objtype = cvar[1],
                            "inetnum" = cvar[2],
                            netname = "",
                            descr = "",
                            country = "",
                            org = "",
                            geoloc = "",
                            language = "",
                            admin.c = "",
                            tech.c = "",
                            rev.srv = "",
                            status = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            mnt.routes = "",
                            mnt.irt = "",
                            abuse.mailbox = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "inet.rtr" = {
           wo <- data.frame(objtype = cvar[1],
                            "inet.rtr" = cvar[2],
                            descr = "",
                            alias = "",
                            local.as = "",
                            ifaddr = "",
                            peer = "",
                            mp.peer = "",
                            member.of = "",
                            remarks = "",
                            org = "",
                            admin.c = "",
                            tech.c = "",
                            notify = "",
                            mnt.by = "",
                            created = "",
                            last.modified = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "irt" = {
           wo <- data.frame(objtype = cvar[1],
                            "irt" = cvar[2],
                            address = "",
                            country = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            abuse.mailbox = "",
                            signature = "",
                            encryption = "",
                            org = "",
                            admin.c = "",
                            tech.c = "",
                            auth = "",
                            remarks = "",
                            irt.nfy = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "key.cert" = {
           wo <- data.frame(objtype = cvar[1],
                            "key.cert" = cvar[2],
                            method = "",
                            owner = "",
                            org = "",
                            country = "",
                            fingerpr = "",
                            certif = "",
                            remarks = "",
                            notify = "",
                            admin.c = "",
                            tech.c = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "limerick" = {
           wo <- data.frame(objtype = cvar[1],
                            "limerick" = cvar[2],
                            descr = "",
                            text = "",
                            admin.c = "",
                            author = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "mntner" = {
           wo <- data.frame(objtype = cvar[1],
                            "mntner" = cvar[2],
                            descr = "",
                            country = "",
                            org = "",
                            admin.c = "",
                            tech.c = "",
                            upd.to = "",
                            mnt.nfy = "",
                            auth = "",
                            remarks = "",
                            notify = "",
                            abuse.mailbox = "",
                            mnt.by = "",
                            referral.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "peering.set" = {
           wo <- data.frame(objtype = cvar[1],
                            "peering.set" = cvar[2],
                            descr = "",
                            peering = "",
                            mp.peering = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "person" = {
           wo <- data.frame(objtype = cvar[1],
                            "person" = cvar[2],
                            org = "",
                            descr = "",
                            address = "",
                            country = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            nic.hdl = "",
                            remarks = "",
                            notify = "",
                            abuse.mailbox = "",
                            admin.c = "",
                            tech.c = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "role" = {
           wo <- data.frame(objtype = cvar[1],
                            "role" = cvar[2],
                            address = "",
                            org = "",
                            country = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            trouble = "",
                            admin.c = "",
                            tech.c = "",
                            nic.hdl = "",
                            remarks = "",
                            descr = "",
                            notify = "",
                            abuse.mailbox = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "route" = {
           wo <- data.frame(objtype = cvar[1],
                            "route" = cvar[2],
                            descr = "",
                            country = "",
                            origin = "",
                            holes = "",
                            member.of = "",
                            inject = "",
                            aggr.mtd = "",
                            aggr.bndry = "",
                            export.comps = "",
                            components = "",
                            remarks = "",
                            admin.c = "",
                            tech.c = "",
                            cross.mnt = "",
                            cross.nfy = "",
                            notify = "",
                            mnt.lower = "",
                            mnt.routes = "",
                            mnt.by = "",
                            org = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "route6" = {
           wo <- data.frame(objtype = cvar[1],
                            "route6" = cvar[2],
                            descr = "",
                            country = "",
                            origin = "",
                            holes = "",
                            org = "",
                            member.of = "",
                            inject = "",
                            aggr.mtd = "",
                            aggr.bndry = "",
                            export.comps = "",
                            components = "",
                            remarks = "",
                            admin.c = "",
                            tech.c = "",
                            notify = "",
                            mnt.lower = "",
                            mnt.routes = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "route.set" = {
           wo <- data.frame(objtype = cvar[1],
                            "route.set" = cvar[2],
                            descr = "",
                            members = "",
                            mp.members = "",
                            mbrs.by.ref = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "rtr.set" = {
           wo <- data.frame(objtype = cvar[1],
                            "rtr.set" = cvar[2],
                            descr = "",
                            members = "",
                            mp.members = "",
                            mbrs.by.ref = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            mnt.lower = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         {print("default case")})
  return(wo)
}
