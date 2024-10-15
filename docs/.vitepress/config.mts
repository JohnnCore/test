import { defineConfig } from 'vitepress'
import { tabsMarkdownPlugin } from 'vitepress-plugin-tabs'
import githubAlertsPlugin from './plugins/githubAlertsPlugin';
import youtubeEmbedPlugin from './plugins/youtubeEmbedPlugin';
import lineNumberPlugin from './plugins/lineNumbers';
/*import { linkToCardPlugin } from '@luckrya/markdown-it-link-to-card';
import type { LinkToCardPluginOptions } from '@luckrya/markdown-it-link-to-card';*/




// https://vitepress.dev/reference/site-config
export default defineConfig({
    base:'/PenTest-Cheat-Sheet/',
    title: "The Hacker Recipes",
    srcDir: 'src',
    description: "The Hacker Recipes is aimed at freely providing technical guides on various hacking topics",
    cleanUrls: true,
    lastUpdated: true,
    sitemap: {
        hostname: 'https://thehacker.recipes'
    },
    head: [
        ['meta', { name: 'theme-color', content: '#1b1b1f' }],
        ['link', { rel: 'apple-touch-icon', sizes: '180x180', href: '/images/apple-touch-icon.png' }],
        ['link', { rel: 'icon', href: '/images/favicon.ico' }],
        ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/images/favicon-32x32.png' }],
        ['link', { rel: 'icon', type: 'image/png', sizes: '16x16', href: '/images/favicon-16x16.png' }],
        ['link', { rel: 'manifest', href: '/images/site.webmanifest' }],
        ['link', { rel: 'mask-icon', href: '/images/safari-pinned-tab.svg', color: '#5bbad5' }],
        ['meta', { name: 'msapplication-TileColor', content: '#da532c' }],
        ['link', { rel: 'stylesheet', href: 'https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,1,0' }],
        ['script', { async: '', src: 'https://www.googletagmanager.com/gtag/js?id=G-211RDJSM3Y' }],
        ['script', {}, "window.dataLayer = window.dataLayer || [];\nfunction gtag(){dataLayer.push(arguments);}\ngtag('js', new Date());\ngtag('config', 'G-211RDJSM3Y');" ]
    ],
    transformHead: ({ pageData }) => {
        const pageTitle = pageData.title ? `${pageData.title} | The Hacker Recipes` : 'The Hacker Recipes';
        const pageDescription = pageData.description || 'Comprehensive cybersecurity guides and strategies for ethical hacking and penetration testing';
        return [
            ['title', {}, pageTitle],
            ['meta', { property: 'og:title', content: pageTitle }],
            ['meta', { property: 'og:description', content: pageDescription }],
            ['meta', { property: 'og:image', content: 'https://thehacker.recipes/images/social-preview.png' }],
            ['meta', { name: 'twitter:title', content: pageTitle }],
            ['meta', { name: 'twitter:image', content: 'https://thehacker.recipes/images/social-preview.png' }],
            ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
            ['meta', { name: 'twitter:description', content: pageDescription }]
        ];
    },
    themeConfig: {
        logo: {
            dark: '/images/logo.svg',
            light: '/images/logo.svg'
        },
        /*carbonAds: {
          code: 'SOMETHING',
          placement: 'idontknow'
        },*/
        search: {
            provider: 'local'
        },
        nav: [
            // { text: 'Tools', link: 'https://tools.thehacker.recipes/' },
            // { text: 'Exegol', link: 'https://exegol.readthedocs.io/en/latest/' },
        ],
        outline: "deep",
        sidebar: [
            {
                "text": "Active Directory",
                "collapsed": false,
                "items": [
                    {
                        "text": "Reconnaissance",
                        "link": "/ad/recon/index.md",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "DHCP",
                                "link": "/ad/recon/dhcp.md",
                            },
                            {
                                "text": "DNS",
                                "link": "/ad/recon/dns.md",
                            },
                            {
                                "text": "NBT-NS",
                                "link": "/ad/recon/nbt-ns.md"
                            },
                            {
                                "text": "Responder ⚙️",
                                "link": "/ad/recon/responder.md"
                            },
                            {
                                "text": "Port scanning",
                                "link": "/ad/recon/port-scanning.md"
                            },
                            {
                                "text": "LDAP",
                                "link": "/ad/recon/ldap.md"
                            },
                            {
                                "text": "BloodHound ⚙️",
                                "link": "/ad/recon/bloodhound/index.md"
                            },
                            {
                                "text": "MS-RPC",
                                "link": "/ad/recon/ms-rpc.md"
                            },
                            {
                                "text": "enum4linux ⚙️",
                                "link": "/ad/recon/enum4linux.md"
                            },
                            {
                                "text": "Password policy",
                                "link": "/ad/recon/password-policy.md"
                            }
                        ]
                    },
                    {
                        "text": "Movement",
                        "collapsed": true,
                        "link": "/ad/movement/index.md",
                        "items": [
                            {
                                "text": "Credentials",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Dumping",
                                        "link": "/ad/movement/credentials/dumping/index.md",
                                        "collapsed": true,
                                        "items": [
                                            {
                                                "text": "SAM & LSA secrets",
                                                "link": "/ad/movement/credentials/dumping/sam-and-lsa-secrets.md"
                                            },
                                            {
                                                "text": "DPAPI secrets",
                                                "link": "/ad/movement/credentials/dumping/dpapi-protected-secrets.md"
                                            },
                                            {
                                                "text": "NTDS secrets",
                                                "link": "/ad/movement/credentials/dumping/ntds.md"
                                            },
                                            {
                                                "text": "LSASS secrets",
                                                "link": "/ad/movement/credentials/dumping/lsass.md"
                                            },
                                            {
                                                "text": "DCSync",
                                                "link": "/ad/movement/credentials/dumping/dcsync.md"
                                            },
                                            {
                                                "text": "Group Policy Preferences",
                                                "link": "/ad/movement/credentials/dumping/group-policies-preferences.md"
                                            },
                                            {
                                                "text": "Network shares",
                                                "link": "/ad/movement/credentials/dumping/network-shares.md"
                                            },
                                            {
                                                "text": "Network protocols",
                                                "link": "/ad/movement/credentials/dumping/network-protocols.md"
                                            },
                                            {
                                                "text": "Web browsers",
                                                "link": "/ad/movement/credentials/dumping/web-browsers.md"
                                            },
                                            {
                                                "text": "In-memory secrets",
                                                "link": "/ad/movement/credentials/dumping/in-memory.md"
                                            },
                                            {
                                                "text": "Kerberos key list",
                                                "link": "/ad/movement/credentials/dumping/kerberos-key-list.md"
                                            },
                                            {
                                                "text": "🛠️ Cached Kerberos tickets",
                                                "link": "/ad/movement/credentials/dumping/cached-kerberos-tickets.md"
                                            },
                                            {
                                                "text": "Windows Credential Manager",
                                                "link": "/ad/movement/credentials/dumping/windows-credential-manager.md"
                                            },
                                            {
                                                "text": "🛠️ Local files",
                                                "link": "/ad/movement/credentials/dumping/local-files.md"
                                            },
                                            {
                                                "text": "🛠️ Password managers",
                                                "link": "/ad/movement/credentials/dumping/password-managers.md"
                                            }
                                        ]
                                    },
                                    {
                                        "text": "Cracking",
                                        "link": "/ad/movement/credentials/cracking.md"
                                    },
                                    {
                                        "text": "Bruteforcing",
                                        "collapsed": true,
                                        "items": [
                                            {
                                                "text": "Guessing",
                                                "link": "/ad/movement/credentials/bruteforcing/guessing.md"
                                            },
                                            {
                                                "text": "Spraying",
                                                "link": "/ad/movement/credentials/bruteforcing/spraying.md"
                                            },
                                            {
                                                "text": "Stuffing",
                                                "link": "/ad/movement/credentials/bruteforcing/stuffing.md"
                                            }
                                        ]
                                    },
                                    {
                                        "text": "Shuffling",
                                        "link": "/ad/movement/credentials/shuffling.md"
                                    },
                                    {
                                        "text": "Impersonation",
                                        "link": "/ad/movement/credentials/impersonation.md"
                                    }
                                ]
                            },
                            {
                                "text": "MITM and coerced auths",
                                "link": "/ad/movement/mitm-and-coerced-authentications/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "ARP poisoning",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/arp-poisoning.md"
                                    },
                                    {
                                        "text": "DNS spoofing",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/dns-spoofing.md"
                                    },
                                    {
                                        "text": "DHCP poisoning",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/dhcp-poisoning.md"
                                    },
                                    {
                                        "text": "DHCPv6 spoofing",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/dhcpv6-spoofing.md"
                                    },
                                    {
                                        "text": "WSUS spoofing",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/wsus-spoofing.md"
                                    },
                                    {
                                        "text": "LLMNR, NBT-NS, mDNS spoofing",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing.md"
                                    },
                                    {
                                        "text": "ADIDNS poisoning",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/adidns-spoofing.md"
                                    },
                                    {
                                        "text": "WPAD spoofing",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/wpad-spoofing.md"
                                    },
                                    {
                                        "text": "MS-EFSR abuse (PetitPotam)",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/ms-efsr.md"
                                    },
                                    {
                                        "text": "MS-RPRN abuse (PrinterBug)",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/ms-rprn.md"
                                    },
                                    {
                                        "text": "MS-FSRVP abuse (ShadowCoerce)",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/ms-fsrvp.md"
                                    },
                                    {
                                        "text": "MS-DFSNM abuse (DFSCoerce)",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/ms-dfsnm.md"
                                    },
                                    {
                                        "text": "PushSubscription abuse",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/pushsubscription-abuse.md"
                                    },
                                    {
                                        "text": "WebClient abuse (WebDAV)",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/webclient.md"
                                    },
                                    {
                                        "text": "🛠️ NBT Name Overwrite",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/nbt-name-overwrite.md"
                                    },
                                    {
                                        "text": "🛠️ ICMP Redirect",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/icmp-redirect.md"
                                    },
                                    {
                                        "text": "🛠️ Living off the land",
                                        "link": "/ad/movement/mitm-and-coerced-authentications/living-off-the-land.md"
                                    }
                                ]
                            },
                            {
                                "text": "NTLM",
                                "link": "/ad/movement/ntlm/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Capture",
                                        "link": "/ad/movement/ntlm/capture.md"
                                    },
                                    {
                                        "text": "Relay",
                                        "link": "/ad/movement/ntlm/relay.md"
                                    },
                                    {
                                        "text": "Pass the hash",
                                        "link": "/ad/movement/ntlm/pth.md"
                                    }
                                ]
                            },
                            {
                                "text": "Kerberos",
                                "link": "/ad/movement/kerberos/index.md",
                                "collapsed": true,
                                "items": [

                                    {
                                        "text": "Pass the key/ Overpass the hash",
                                        "link": "/zNew/ActiveDirectory/Movement/Kerberos/PassTheKeyOverPassTheHash.md"
                                    },
                                    {
                                        "text": "Pass the ticket",
                                        "link": "/zNew/ActiveDirectory/Movement/Kerberos/PassTheTicket.md"
                                    },
                                ]
                            },
                            {
                                "text": "DACL abuse",
                                "link": "/ad/movement/dacl/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "AddMember",
                                        "link": "/ad/movement/dacl/addmember.md"
                                    },
                                    {
                                        "text": "ForceChangePassword",
                                        "link": "/ad/movement/dacl/forcechangepassword.md"
                                    },
                                    {
                                        "text": "Targeted Kerberoasting",
                                        "link": "/ad/movement/dacl/targeted-kerberoasting.md"
                                    },
                                    {
                                        "text": "ReadLAPSPassword",
                                        "link": "/ad/movement/dacl/readlapspassword.md"
                                    },
                                    {
                                        "text": "ReadGMSAPassword",
                                        "link": "/ad/movement/dacl/readgmsapassword.md"
                                    },
                                    {
                                        "text": "Grant ownership",
                                        "link": "/ad/movement/dacl/grant-ownership.md"
                                    },
                                    {
                                        "text": "Grant rights",
                                        "link": "/ad/movement/dacl/grant-rights.md"
                                    },
                                    {
                                        "text": "Logon script",
                                        "link": "/ad/movement/dacl/logon-script.md"
                                    },
                                    {
                                        "text": "Rights on RODC object",
                                        "link": "/ad/movement/dacl/rights-on-rodc-object.md"
                                    }
                                ]
                            },
                            {
                                "text": "Group policies",
                                "link": "/ad/movement/group-policies.md"
                            },
                            {
                                "text": "Trusts",
                                "link": "/ad/movement/trusts/index.md",
                            },
                            {
                                "text": "Netlogon",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "ZeroLogon",
                                        "link": "/ad/movement/netlogon/zerologon.md"
                                    }
                                ]
                            },
                            {
                                "text": "Certificate Services (AD-CS)",
                                "link": "/ad/movement/adcs/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Certificate templates",
                                        "link": "/ad/movement/adcs/certificate-templates.md"
                                    },
                                    {
                                        "text": "Certificate authority",
                                        "link": "/ad/movement/adcs/certificate-authority.md"
                                    },
                                    {
                                        "text": "Access controls",
                                        "link": "/ad/movement/adcs/access-controls.md"
                                    },
                                    {
                                        "text": "Unsigned endpoints",
                                        "link": "/ad/movement/adcs/unsigned-endpoints.md"
                                    },
                                    {
                                        "text": "Certifried",
                                        "link": "/ad/movement/adcs/certifried.md"
                                    }
                                ]
                            },
                            {
                                "text": "SCCM / MECM",
                                "link": "/ad/movement/sccm-mecm/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Privilege escalation",
                                        "link": "/ad/movement/sccm-mecm/privilege-escalation.md"
                                    },
                                    {
                                        "text": "Lateral movement",
                                        "link": "/ad/movement/sccm-mecm/lateral-movement.md"
                                    }
                                ]
                            },
                            {
                                "text": "Exchange services",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "🛠️ PrivExchange",
                                        "link": "/ad/movement/exchange-services/privexchange.md"
                                    },
                                    {
                                        "text": "🛠️ ProxyLogon",
                                        "link": "/ad/movement/exchange-services/proxylogon.md"
                                    },
                                    {
                                        "text": "🛠️ ProxyShell",
                                        "link": "/ad/movement/exchange-services/proxyshell.md"
                                    }
                                ]
                            },
                            {
                                "text": "Print Spooler Service",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "PrinterBug",
                                        "link": "/ad/movement/print-spooler-service/printerbug.md"
                                    },
                                    {
                                        "text": "PrintNightmare",
                                        "link": "/ad/movement/print-spooler-service/printnightmare.md"
                                    }
                                ]
                            },
                            {
                                "text": "Schannel",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Pass the Certificate",
                                        "link": "/ad/movement/schannel/passthecert.md"
                                    }
                                ]
                            },
                            {
                                "text": "Built-ins & settings",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Security groups",
                                        "link": "/ad/movement/builtins/security-groups.md"
                                    },
                                    {
                                        "text": "MachineAccountQuota",
                                        "link": "/ad/movement/builtins/machineaccountquota.md"
                                    },
                                    {
                                        "text": "Pre-Windows 2000 computers",
                                        "link": "/ad/movement/builtins/pre-windows-2000-computers.md"
                                    },
                                    {
                                        "text": "RODC",
                                        "link": "/ad/movement/builtins/rodc.md"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "text": "Persistence",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "DC Shadow",
                                "link": "/ad/persistence/dcshadow/index.md"
                            },
                            {
                                "text": "SID History",
                                "link": "/ad/persistence/sid-history.md"
                            },
                            {
                                "text": "Skeleton key",
                                "link": "/ad/persistence/skeleton-key/index.md"
                            },
                            {
                                "text": "GoldenGMSA",
                                "link": "/ad/persistence/goldengmsa.md"
                            },
                            {
                                "text": "AdminSDHolder",
                                "link": "/ad/persistence/adminsdholder.md"
                            },
                            {
                                "text": "Kerberos",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Forged tickets",
                                        "link": "/ad/persistence/kerberos/forged-tickets.md"
                                    },
                                    {
                                        "text": "Delegation to KRBTGT",
                                        "link": "/ad/persistence/kerberos/delegation-to-krbtgt.md"
                                    }
                                ]
                            },
                            {
                                "text": "Certificate Services (AD-CS)",
                                "link": "/ad/persistence/adcs/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Certificate authority",
                                        "link": "/ad/persistence/adcs/certificate-authority.md"
                                    },
                                    {
                                        "text": "Access controls",
                                        "link": "/ad/persistence/adcs/access-controls.md"
                                    },
                                    {
                                        "text": "🛠️ Golden certificate",
                                        "link": "/ad/persistence/adcs/golden-certificate.md"
                                    }
                                ]
                            },
                            {
                                "text": "🛠️ DACL abuse",
                                "link": "/ad/persistence/dacl.md"
                            },
                            {
                                "text": "Shadow Principals (PAM)",
                                "link": "/ad/persistence/shadow-principals.md"
                            }
                        ]
                    }
                ]
            },
            {
                "text": "Web services",
                "collapsed": false,
                "items": [
                    {
                        "text": "Reconnaissance",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "HTTP response headers",
                                "link": "/web/recon/http-banners.md"
                            },
                            {
                                "text": "Comments and metadata",
                                "link": "/web/recon/comments-and-metadata.md"
                            },
                            {
                                "text": "Error messages",
                                "link": "/web/recon/error-messages.md"
                            },
                            {
                                "text": "Site crawling",
                                "link": "/web/recon/site-crawling.md"
                            },
                            {
                                "text": "Directory fuzzing",
                                "link": "/web/recon/directory-fuzzing.md"
                            },
                            {
                                "text": "Subdomains enumeration",
                                "link": "/web/recon/domains-enumeration.md"
                            },
                            {
                                "text": "Subdomain & vhost fuzzing",
                                "link": "/web/recon/virtual-host-fuzzing.md"
                            },
                            {
                                "text": "Web Application Firewall (WAF)",
                                "link": "/web/recon/waf-fingerprinting.md"
                            },
                            {
                                "text": "Content Management System (CMS)",
                                "link": "/web/recon/cms.md"
                            },
                            {
                                "text": "Other technologies",
                                "link": "/web/recon/web-technologies.md"
                            },
                            {
                                "text": "Known vulnerabilities",
                                "link": "/web/recon/known-vulnerabilities.md"
                            }
                        ]
                    },
                    {
                        "text": "Configuration",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "Default credentials",
                                "link": "/web/config/default-credentials.md"
                            },
                            {
                                "text": "HTTP methods",
                                "link": "/web/config/http-methods.md"
                            },
                            {
                                "text": "HTTP security headers",
                                "link": "/web/config/http-headers/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "Clickjacking",
                                        "link": "/web/config/http-headers/clickjacking/index.md"
                                    },
                                    {
                                        "text": "MIME type sniffing",
                                        "link": "/web/config/http-headers/mime-sniffing.md"
                                    },
                                    {
                                        "text": "🛠️ CORS (Cross-Origin Resource Sharing)",
                                        "link": "/web/config/http-headers/cors/index.md"
                                    },
                                    {
                                        "text": "🛠️ CSP (Content Security Policy)",
                                        "link": "/web/config/http-headers/csp-content-security-policy.md"
                                    }
                                ]
                            },
                            {
                                "text": "HTTP request smuggling",
                                "link": "/web/config/http-request-smuggling/index.md"
                            },
                            {
                                "text": "HTTP response splitting",
                                "link": "/web/config/http-response-splitting.md"
                            },
                            {
                                "text": "Insecure Cookies",
                                "link": "/web/config/insecure-cookies.md"
                            },
                            {
                                "text": "Denial of Service (DoS)",
                                "link": "/web/config/dos-mitigations.md"
                            },
                            {
                                "text": "Identity and Access Management",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "🛠️ OAuth 2.0",
                                        "link": "/web/config/identity-and-access-management/oauth-2.0.md"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "text": "Accounts and sessions",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "Security policies",
                                "link": "/web/accounts-and-sessions/security-policies.md"
                            },
                            {
                                "text": "Password change",
                                "link": "/web/accounts-and-sessions/password-change.md"
                            },
                            {
                                "text": "🛠️ Password reset",
                                "link": "/web/accounts-and-sessions/password-reset.md"
                            },
                            {
                                "text": "Account creation",
                                "link": "/web/accounts-and-sessions/signing-in.md"
                            },
                            {
                                "text": "🛠️ Account deletion",
                                "link": "/web/accounts-and-sessions/account-deletion.md"
                            },
                            {
                                "text": "🛠️ Logging in",
                                "link": "/web/accounts-and-sessions/logging-in.md"
                            }
                        ]
                    },
                    {
                        "text": "User inputs",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "File inclusion",
                                "link": "/web/inputs/file-inclusion/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "LFI to RCE",
                                        "collapsed": true,
                                        "items": [
                                            {
                                                "text": "logs poisoning",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning.md"
                                            },
                                            {
                                                "text": "phpinfo",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/phpinfo.md"
                                            },
                                            {
                                                "text": "file upload",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/file-upload.md"
                                            },
                                            {
                                                "text": "PHP wrappers and streams",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/php-wrappers-and-streams.md"
                                            },
                                            {
                                                "text": "PHP session",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/php-session.md"
                                            },
                                            {
                                                "text": "/proc",
                                                "link": "/web/inputs/file-inclusion/lfi-to-rce/proc.md"
                                            }
                                        ]
                                    },
                                    {
                                        "text": "RFI to RCE",
                                        "link": "/web/inputs/file-inclusion/rfi-to-rce.md"
                                    }
                                ]
                            },
                            {
                                "text": "Unrestricted file upload",
                                "link": "/web/inputs/unrestricted-file-upload.md"
                            },
                            {
                                "text": "SQL injection",
                                "link": "/web/inputs/sqli.md"
                            },
                            {
                                "text": "XSS (Cross-Site Scripting)",
                                "link": "/web/inputs/xss.md"
                            },
                            {
                                "text": "CSRF (Cross-Site Request Forgery)",
                                "link": "/web/inputs/csrf.md"
                            },
                            {
                                "text": "SSRF (Server-Side Request Forgery)",
                                "link": "/web/inputs/ssrf/index.md"
                            },
                            {
                                "text": "IDOR (Insecure Direct Object Reference)",
                                "link": "/web/inputs/idor.md"
                            },
                            {
                                "text": "ORED Open redirect",
                                "link": "/web/inputs/ored.md"
                            },
                            {
                                "text": "Content-Type juggling",
                                "link": "/web/inputs/content-type-juggling/index.md"
                            },
                            {
                                "text": "XXE injection",
                                "link": "/web/inputs/xxe-injection/index.md"
                            },
                            {
                                "text": "Insecure JSON Web Tokens",
                                "link": "/web/inputs/jwt.md"
                            },
                            {
                                "text": "🛠️ HTTP parameter pollution",
                                "link": "/web/inputs/http-parameter-pollution.md"
                            },
                            {
                                "text": "🛠️ SSTI (Server-Side Template Injection)",
                                "link": "/web/inputs/ssti.md"
                            },
                            {
                                "text": "🛠️ Insecure deserialization",
                                "link": "/web/inputs/insecure-deserialization.md"
                            },
                            {
                                "text": "🛠️ CRLF injection",
                                "link": "/web/inputs/crlf-injection.md"
                            },
                            {
                                "text": "🛠️ Arbitrary file download",
                                "link": "/web/inputs/arbitrary-file-download.md"
                            },
                            {
                                "text": "🛠️ Directory traversal",
                                "link": "/web/inputs/directory-traversal.md"
                            },
                            {
                                "text": "🛠️ Null-byte injection",
                                "link": "/web/inputs/null-byte-injection.md"
                            }
                        ]
                    }
                ]
            },
            {
                "text": "Systems & services",
                "collapsed": true,
                "items": [
                    {
                        "text": "Reconnaissance",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "🛠️ Hosts discovery",
                                "link": "/infra/recon/hosts-discovery.md"
                            },
                            {
                                "text": "Port scanning",
                                "link": "/infra/recon/port-scanning.md"
                            }
                        ]
                    },
                    {
                        "text": "Initial access (protocols)",
                        "link": "/infra/protocols/index.md",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "🛠️ FTP",
                                "link": "/infra/protocols/ftp.md"
                            },
                            {
                                "text": "🛠️ SSH",
                                "link": "/infra/protocols/ssh.md"
                            },
                            {
                                "text": "🛠️ Telnet",
                                "link": "/infra/protocols/telnet.md"
                            },
                            {
                                "text": "🛠️ DNS",
                                "link": "/infra/protocols/dns.md"
                            },
                            {
                                "text": "🛠️ HTTP",
                                "link": "/infra/protocols/http.md"
                            },
                            {
                                "text": "🛠️ Kerberos",
                                "link": "/infra/protocols/kerberos.md"
                            },
                            {
                                "text": "🛠️ LDAP",
                                "link": "/infra/protocols/ldap.md"
                            },
                            {
                                "text": "🛠️ SMB",
                                "link": "/infra/protocols/smb.md"
                            },
                            {
                                "text": "🛠️ RTSP",
                                "link": "/infra/protocols/rtsp.md"
                            },
                            {
                                "text": "🛠️ MSSQL",
                                "link": "/infra/protocols/mssql.md"
                            },
                            {
                                "text": "🛠️ NFS",
                                "link": "/infra/protocols/nfs.md"
                            },
                            {
                                "text": "🛠️ MySQL",
                                "link": "/infra/protocols/mysql.md"
                            },
                            {
                                "text": "🛠️ WinRM",
                                "link": "/infra/protocols/winrm.md"
                            }
                        ]
                    },
                    {
                        "text": "Initial access (phishing)",
                        "link": "/infra/phishing.md"
                    },
                    {
                        "text": "Privilege escalation",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "Windows",
                                "link": "/infra/privilege-escalation/windows/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "🛠️ Credential dumping",
                                        "link": "/infra/privilege-escalation/windows/credential-dumping.md"
                                    },
                                    {
                                        "text": "🛠️ Unquoted path",
                                        "link": "/infra/privilege-escalation/windows/unquoted-service-paths.md"
                                    },
                                    {
                                        "text": "🛠️ Scheduled tasks",
                                        "link": "/infra/privilege-escalation/windows/scheduled-tasks.md"
                                    },
                                    {
                                        "text": "🛠️ Weak service permissions",
                                        "link": "/infra/privilege-escalation/windows/weak-service-permissions.md"
                                    },
                                    {
                                        "text": "🛠️ Vulnerable drivers",
                                        "link": "/infra/privilege-escalation/windows/vulnerable-drivers.md"
                                    },
                                    {
                                        "text": "🛠️ Account privileges",
                                        "link": "/infra/privilege-escalation/windows/account-privileges.md"
                                    },
                                    {
                                        "text": "🛠️ Kernel exploitation",
                                        "link": "/infra/privilege-escalation/windows/kernel-exploitation.md"
                                    },
                                    {
                                        "text": "🛠️ Windows Subsystem for Linux",
                                        "link": "/infra/privilege-escalation/windows/windows-subsystem-for-linux.md"
                                    },
                                    {
                                        "text": "🛠️ Runas saved creds",
                                        "link": "/infra/privilege-escalation/windows/runas-saved-creds.md"
                                    },
                                    {
                                        "text": "Unattend files",
                                        "link": "/infra/privilege-escalation/windows/unattend-files.md"
                                    },
                                    {
                                        "text": "🛠️ Network secrets",
                                        "link": "/infra/privilege-escalation/unix/network-secrets.md"
                                    },
                                    {
                                        "text": "🛠️ Living off the land",
                                        "link": "/infra/privilege-escalation/windows/living-off-the-land.md"
                                    }
                                ]
                            },
                            {
                                "text": "UNIX-like",
                                "link": "/infra/privilege-escalation/unix/index.md",
                                "collapsed": true,
                                "items": [
                                    {
                                        "text": "SUDO",
                                        "link": "/infra/privilege-escalation/unix/sudo.md"
                                    },
                                    {
                                        "text": "SUID/SGID binaries",
                                        "link": "/infra/privilege-escalation/unix/suid-sgid-binaries.md"
                                    },
                                    {
                                        "text": "🛠️ Capabilities",
                                        "link": "/infra/privilege-escalation/unix/capabilities.md"
                                    },
                                    {
                                        "text": "🛠️ Network secrets",
                                        "link": "/infra/privilege-escalation/windows/network-secrets.md"
                                    },
                                    {
                                        "text": "🛠️ Living off the land",
                                        "link": "/infra/privilege-escalation/unix/living-off-the-land.md"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "text": "Pivoting",
                        "collapsed": true,
                        "items": [
                            {
                                "text": "🛠️ Port forwarding",
                                "link": "/infra/pivoting/port-forwarding.md"
                            },
                            {
                                "text": "🛠️ SOCKS proxy",
                                "link": "/infra/pivoting/socks-proxy.md"
                            }
                        ]
                    }
                ]
            },
        
        ],
        socialLinks: [
            { icon: 'github', link: 'https://github.com/The-Hacker-Recipes/The-Hacker-Recipes' },
            // { icon: 'x', link: 'https://x.com/_nwodtuhs' },
            // { icon: 'linkedin', link: 'https://www.linkedin.com/in/nwodtuhs/' }
        ],
        editLink: {
            // text: "Contribute to this page",
            // pattern: 'https://github.com/The-Hacker-Recipes/The-Hacker-Recipes/edit/main/docs/src/:path'
        }
    },
    markdown: {
        config(md) {
            md.use(tabsMarkdownPlugin);
            md.use(githubAlertsPlugin);
            md.use(youtubeEmbedPlugin);
            md.use(lineNumberPlugin);
            /*md.use<LinkToCardPluginOptions>(linkToCardPlugin, {
                width: '100%',
            });*/
        }
    },
})
