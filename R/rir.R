#' getRIRs
#'
#' @return
#' @export
#'
#' @examples
getRIRs <- function(){
  ripe.url.dg <- "ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest"
  apnic.url.dg <- "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest"
  arin.url.dg <- "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
  lacnic.url.dg <- "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
  afrinic.url.dg <- "ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"

  rir.urls <- c(ripe.url.dg,apnic.url.dg,arin.url.dg,lacnic.url.dg,afrinic.url.dg)

  rir1 <- getOneRIR(rir.urls[1])
  rir2 <- getOneRIR(rir.urls[2])
  rir3 <- getOneRIR(rir.urls[3])
  rir4 <- getOneRIR(rir.urls[4])
  rir5 <- getOneRIR(rir.urls[5])
  rirs <- dplyr::bind_rows(rir1, rir2, rir3, rir4, rir5)

  # Tidy data
  rirs$registry <- as.factor(rirs$registry)
  rirs$cc <- as.factor(rirs$cc)
  rirs$type <- as.factor(rirs$type)
  rirs$value <- as.integer(rirs$value)
  rirs$date <- as.POSIXct.POSIXlt(strptime(x = rirs$date, format = "%Y%m%d"))
  rirs$status <- as.factor(rirs$status)
  # add CIDR column
  rirs <-  dplyr::mutate(rirs,
                         cidr = ifelse(type == "ipv4",
                                       paste(rirs$start, as.character(32 - log(rirs$value,2)), sep = "/"),
                                       NA))
  # add end ip column
  rirs <-  dplyr::mutate(rirs,
                         end = ifelse(type == "ipv4",
                                      iptools::numeric_to_ip(iptools::ip_to_numeric(rirs$start) + rirs$value - 1),
                                      NA))
  # add ips as num
  rirs <-  dplyr::mutate(rirs,
                         endnum = ifelse(type == "ipv4",
                                         iptools::ip_to_numeric(rirs$start) + rirs$value - 1,
                                         NA))
  rirs <-  dplyr::mutate(rirs,
                         startnum = ifelse(type == "ipv4",
                                           iptools::ip_to_numeric(rirs$start),
                                           NA))
  # Column names and order
  col.names <- c("registry", "country", "type", "start", "ipcount", "date",
                 "status", "opaque.id", "cidr", "end", "endnum", "startnum")
  names(rirs) <- col.names
  col.names <- c("registry", "country", "type", "start", "end", "cidr", "date",
                 "status", "opaque.id", "startnum", "endnum", "ipcount")
  rirs <- rirs[,col.names]

  return(rirs)
}

#' getOneRIR
#'
#' @param url
#'
#' @return
#'
#' @examples
getOneRIR <- function(url = "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest"){
  rir.dg <- read.csv(file = url,
                     header = F, sep = "|", as.is = T, skip = 0,
                     col.names = c("registry", "cc", "type", "start", "value", "date", "status", "opaque-id"),
                     colClasses = c("character", "character", "character", "character", "integer", "character", "character", "character"))
  # extract version
  cond <- which(rir.dg$registry %in% c("2","2.3"))
  if (length(cond) > 0) {
    rir.version <- rir.dg[cond,]
    rir.dg <- rir.dg[-cond,]
  }

  # remove summary
  cond <- which(rir.dg$cc == "*")
  if (length(cond) > 0) rir.dg <- rir.dg[-cond,]

  # remove comments
  cond <- which(rir.dg$type == "")
  if (length(cond) > 0) rir.dg <- rir.dg[-cond,]

  # Tidy data
  # rir.dg$date <- as.POSIXct.POSIXlt(strptime(x = rir.dg$date, format = "%Y%m%d"))
  # rir.dg <- dplyr::mutate(rir.dg, cidr = ifelse(type == "ipv4",
  #                                               paste(rir.dg$start, as.character(32 - log(rir.dg$value,2)), sep = "/"),
  #                                               NA))
  return(rir.dg)
}