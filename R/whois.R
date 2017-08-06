#' RIPE: ftp://ftp.ripe.net/ripe/dbase/split/
#' APNIC: https://ftp.apnic.net/apnic/whois/
#' ARIN: https://ftp.arin.net/pub/rr/
#' AFRINIC: ftp://ftp.afrinic.net/pub/dbase/
#' LACNIC: ?? http://www.lacnic.net/en/web/lacnic/manual-8
#' Others: http://www.irr.net/docs/list.html
#'
#' IANA root files: https://www.iana.org/domains/root/files
#'


#' Whois Parser help
#' RIPE Database Reference Manual: ftp://ftp.ripe.net/ripe/docs/ripe-252.txt
#' APNIC Guide: https://www.apnic.net/manage-ip/using-whois/guide/


stopwords <- c("as-block", "as-set", "aut-num", "domain", "filter-set","inet6num",
               "inetnum", "inet-rtr", "irt", "key-cert","limerick", "mntner", "peering-set",
               "person", "role", "route", "route6", "route-set", "rtr-set")
stopwords <- stringr::str_replace(stopwords,"-",".")

# How to generate validwords from previos db
# kk <- processWhois(filepath)
# kkk <- sapply(names(kk), function(x) length(kk[[x]]))
# k2 <- sapply(names(kkk[kkk>0]), function(x) names(kk[[x]][[2]]))
# cat(paste("\"", unique(unlist(k2)), "\"", collapse = ",", sep = ""))
validwords <- c("descr","country","members","mbrs.by.ref","remarks","tech.c","admin.c","notify",
                "mnt.lower","mnt.by","changed","source","as.set","as.name","member.of","import",
                "export","default","cross.mnt","cross.nfy","mnt.routes","mnt.irt","aut.num",
                "netname","geoloc","language","rev.srv","status","inet6num","inetnum","alias",
                "local.as","ifaddr","peer","mp.peer","inet.rtr","method","owner","fingerpr",
                "certif","key.cert","upd.to","mnt.nfy","auth","abuse.mailbox","referral.by",
                "mntner","origin","holes","inject","aggr.mtd","aggr.bndry","export.comps",
                "components","route","org","route6","mp.members","route.set")
validwords <- unique(c(stopwords,validwords))

# Read file line by line
filepath <- "../data/arin.db"


processWhois <-  function(filepath) {
  # New whois data base
  whois.db <- list()
  whois.db <- lapply(stringr::str_replace(stopwords,"-","."), function(x) list())
  names(whois.db) <- stopwords

  # Parse raw file
  i <- 1
  newobject <- TRUE
  current.obj <- ""
  current.obj.type <- ""
  current.var <- ""
  current.var.type <- ""

  con = file(filepath, "r")
  while (TRUE) {
    # if ((current.var.type == "as.set") &&
    #     (length(whois.db[[current.obj.type]]) + 1) %in% c(1825)) {
    #   dummy <- NA
    # }

    # if (i == 42365) {
    #   dummy <- NA
    # }
    line = readLines(con, n = 1)
    if (length(line) == 0) {
      # Save last object
      whois.db[[current.obj.type]][[length(whois.db[[current.obj.type]]) + 1]] <- current.obj
      break
    }
    if (nchar(line) == 0) {
      newobject <- TRUE
      next
    }
    # print(line)

    # New line pre-process
    if (stringr::str_detect(line, ":")) {
      line <- c(stringr::str_replace(stringr::str_sub(line, 1, stringr::str_locate(line, ":")[1] - 1),"-","."),
                stringr::str_trim(stringr::str_sub(line, stringr::str_locate(line, ":")[1] + 1, nchar(line))))
      if (!(line[1] %in% validwords)) {
        line <- stringr::str_trim(paste(line, collapse = ":"))
      } else {
        if (current.obj.type != line[1] && !newobject && i > 1) {
          if (nchar(current.obj[[line[1]]]) > 0) {
            line <- line[2]
          }
        }
      }
    } else {
      line <- stringr::str_trim(line)
    }
    newobject <- FALSE

    switch(as.character(length(line)),
            "1" = {
              # More info for current variable
              #  - add line.txt to current.var
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
              if (current.var.type %in% stopwords) {
                # New Object
                #  - save current.obj in whois.db
                whois.db[[current.obj.type]][[length(whois.db[[current.obj.type]]) + 1]] <- current.obj
                # Initiate current object
                current.obj.type <- current.var.type
                current.obj <- newWhoisObject(current.var)
                print(paste("Element:", i))
                i <- i + 1
              } else {
                # New variable
                #  - add current.var to current.obj
                current.obj[[current.var.type]] <- current.var[2]
              }
            },
            {print("default case")})
  }
  close(con)

  return(whois.db)
}

newWhoisObject <- function(cvar = "") {
  wo <- data.frame()
  switch(cvar[1],
         "as.block" = {
           wo <- data.frame(objtype = cvar[1],
                            "as.block" = cvar[2],
                            descr = "",
                            country = "",
                            remarks = "",
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
                            country = "",
                            member.of = "",
                            import = "",
                            export = "",
                            default = "",
                            remarks = "",
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
                            mp.filter = "",
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
         "inet6num" = {
           wo <- data.frame(objtype = cvar[1],
                            "inet6num" = cvar[2],
                            netname = "",
                            descr = "",
                            country = "",
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
                            admin.c = "",
                            tech.c = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "irt" = {
           wo <- data.frame(objtype = cvar[1],
                            "irt" = cvar[2],
                            address = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            abuse.mailbox = "",
                            signature = "",
                            encryption = "",
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
                            address = "",
                            country = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            nic.hdl = "",
                            remarks = "",
                            notify = "",
                            abuse.mailbox = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "role" = {
           wo <- data.frame(objtype = cvar[1],
                            "role" = cvar[2],
                            address = "",
                            country = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            trouble = "",
                            admin.c = "",
                            tech.c = "",
                            nic.hdl = "",
                            remarks = "",
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
