PORTNAME=	kratos
DISTVERSIONPREFIX=	v
DISTVERSION=	1.3.1
CATEGORIES=	net
DIST_SUBDIR=	${PKGNAMEPREFIX}${PORTNAME}
PKGNAMEPREFIX=	ory-

MAINTAINER=	doceng@FreeBSD.org
COMMENT=	Fast and Flexible Static Site Generator built with love in GoLang
WWW=		https://www.ory.sh/kratos

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		go:1.23,modules
USE_GITHUB= 	yes
USE_RC_SUBR=	kratos

GH_ACCOUNT=	ory
GO_MODULE=	github.com/ory/kratos
GO_BUILDFLAGS=	-ldflags="-X github.com/ory/kratos/driver/config.Version=${PORTVERSION}"

post-fetch:
	@${ECHO_MSG} "Fetching ${GO_MODNAME}/internal/client-go dependency";
	(cd ${DISTDIR}/${DIST_SUBDIR}; [ -e internal/client-go/go.mod ] || (\
		${MKDIR} internal/client-go; \
		${TAR} -zxf ${DISTNAME}${EXTRACT_SUFX} ${PORTNAME}-${PORTVERSION}/internal/client-go/go.mod; \
		${CP} ${PORTNAME}-${PORTVERSION}/internal/client-go/go.mod internal/client-go/go.mod))

post-extract:
	@${CP} -r ${WRKDIR}/${PORTNAME}-${PORTVERSION}/internal/client-go ${GO_WRKSRC}/internal;

post-patch:
	@${SED} -i -e "s;%%PREFIX%%;${PREFIX};g" ${WRKSRC}/contrib/quickstart/kratos/email-password/kratos.yml

post-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/etc/kratos
	${INSTALL_DATA} ${WRKSRC}/contrib/quickstart/kratos/email-password/kratos.yml ${STAGEDIR}${PREFIX}/etc/kratos/kratos.yml.sample
	${INSTALL_DATA} ${WRKSRC}/contrib/quickstart/kratos/email-password/identity.schema.json ${STAGEDIR}${PREFIX}/etc/kratos/identity.schema.json.sample

.include <bsd.port.mk>
