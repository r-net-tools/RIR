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

stopwords <- c("as-block", "as-set", "aut-num", "domain", "filter-set","inet6num",
               "inetnum", "inet-rtr", "irt", "key-cert","limerick", "mntner", "peering-set",
               "person", "role", "route", "route6", "route-set", "rtr-set")

# Read file line by line

filepath <- "../data/arin.db"


processWhois <-  function(filepath) {
  # New whois data base
  whois.db <- list()

  # Parse raw file
  i <- 1
  current.obj <- ""
  current.var <- ""

  con = file(filepath, "r")
  while (TRUE) {
    line = readLines(con, n = 1)
    if ( length(line) == 0 ) {
      # guardar objeto en curso
      break
    }
    # print(line)

    line <- stringr::str_trim(stringr::str_split(string = line,
                                                 pattern = ":",
                                                 n = 2, simplify = T))
    switch(as.character(length(line)),
            "1" = {
              # More info for current variable
              #  - add line.txt to current.var
              current.var[2] <- paste(current.var[2],
                                      line, sep = "\n")
              current.obj[[stringr::str_replace(current.var[1],"-",".")]] <- current.var[2]
            },
            "2" = {
              # New variable
              current.var[1] <- line[1]
              current.var[2] <- line[2]

              if (line[1] %in% stopwords) {
                # New Object
                #  - save current.obj in whois.db
                whois.db[[i]] <- current.obj
                # Initiate current object
                current.obj <- newWhoisObject(current.var)
                i <- i + 1
                print(paste("Element:", i))
                # if (i %in% c(14,697)) {
                #   dummy <- NA
                # }
              } else {
                # New variable
                #  - add current.var to current.obj
                current.obj[[stringr::str_replace(current.var[1],"-",".")]] <- current.var[2]
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
         "as-block" = {
           wo <- data.frame(as.block = cvar[1],
                            descr = "",
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
         "as-set" = {
           wo <- data.frame(as.set = cvar[1],
                            descr = "",
                            members = "",
                            mbrs.by.ref = "",
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
         "aut-num" = {
           wo <- data.frame(aut.num = cvar[1],
                            as.name = "",
                            descr = "",
                            member.of = "",
                            import = "",
                            export = "",
                            default = "",
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
         "domain" = {
           wo <- data.frame(domain = cvar[1],
                            descr = "",
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
         "filter-set" = {
           wo <- data.frame(filter.set = cvar[1],
                            descr = "",
                            filter = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "inet6num" = {
           wo <- data.frame(inet6num = cvar[1],
                            netname = "",
                            descr = "",
                            country = "",
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
           wo <- data.frame(inetnum = cvar[1],
                            netname = "",
                            descr = "",
                            country = "",
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
         "inet-rtr" = {
           wo <- data.frame(inet.rtr = cvar[1],
                            descr = "",
                            alias = "",
                            local.as = "",
                            ifaddr = "",
                            peer = "",
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
           wo <- data.frame(irt = cvar[1],
                            address = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
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
         "key-cert" = {
           wo <- data.frame(key.cert = cvar[1],
                            method = "",
                            owner = "",
                            fingerpr = "",
                            certif = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "limerick" = {
           wo <- data.frame(limerick = cvar[1],
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
           wo <- data.frame(mntner = cvar[1],
                            descr = "",
                            admin.c = "",
                            tech.c = "",
                            upd.to = "",
                            mnt.nfy = "",
                            auth = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            referral.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "peering-set" = {
           wo <- data.frame(peering.set = cvar[1],
                            descr = "",
                            peering = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "person" = {
           wo <- data.frame(person = cvar[1],
                            address = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            nic.hdl = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "role" = {
           wo <- data.frame(role = cvar[1],
                            address = "",
                            phone = "",
                            fax.no = "",
                            e.mail = "",
                            trouble = "",
                            admin.c = "",
                            tech.c = "",
                            nic.hdl = "",
                            remarks = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "route" = {
           wo <- data.frame(route = cvar[1],
                            descr = "",
                            origin = "",
                            holes = "",
                            member.of = "",
                            inject = "",
                            aggr.mtd = "",
                            aggr.bndry = "",
                            export.comps = "",
                            components = "",
                            remarks = "",
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
           # ALERT: not in official documentation, I deduced the fields
           wo <- data.frame(route = cvar[1],
                            descr = "",
                            origin = "",
                            holes = "",
                            member.of = "",
                            inject = "",
                            aggr.mtd = "",
                            aggr.bndry = "",
                            export.comps = "",
                            components = "",
                            remarks = "",
                            cross.mnt = "",
                            cross.nfy = "",
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
         "route-set" = {
           wo <- data.frame(route.set = cvar[1],
                            descr = "",
                            members = "",
                            mbrs.by.ref = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         "rtr-set" = {
           wo <- data.frame(rtr.set = cvar[1],
                            descr = "",
                            members = "",
                            mbrs.by.ref = "",
                            remarks = "",
                            tech.c = "",
                            admin.c = "",
                            notify = "",
                            mnt.by = "",
                            changed = "",
                            source = "",
                            stringsAsFactors = F)
         },
         {print("default case")})
  return(wo)
}
