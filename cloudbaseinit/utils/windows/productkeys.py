# Copyright 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from cloudbaseinit import constant

SKU_TO_PRODUCT_KEY_MAP = {
    # KMS: https://technet.microsoft.com/en-US/jj612867.aspx
    # AVMA: https://technet.microsoft.com/en-us/library/dn303421.aspx

    (6, 1, constant.VOL_ACT_KMS): {
        # Windows 7, Windows server 2008 R2
        "Business": "FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4",
        "BusinessN": "MRPKT-YTG23-K7D7T-X2JMM-QY7MG",
        "BusinessE": "W82YF-2Q76Y-63HXB-FGJG9-GF7QX",
        "Enterprise": "33PXH-7Y6KF-2VJC9-XBBR8-HVTHH",
        "EnterpriseN": "YDRBP-3D83W-TY26F-D46B2-XCKRJ",
        "EnterpriseE": "C29WB-22CC8-VJ326-GHFJW-H9DH4",
        "ServerComputeCluster": "FKJQ8-TMCVP-FRMR7-4WR42-3JCD7",
        "ServerDatacenter": "74YFP-3QFB3-KQT8W-PMXWJ-7M648",
        "ServerEnterprise": "489J6-VHDMP-X63PK-3K798-CPX3Y",
        "ServerEnterpriseIA64": "GT63C-RJFQ3-4GMB6-BRFB9-CB83V",
        "ServerStandard": "YC6KT-GKW9T-YTKYR-T4X34-R7VHC",
        "ServerWeb": "6TPJF-RBVHG-WBW2R-86QPH-6RTM4",
    },

    (6, 2, constant.VOL_ACT_KMS): {
        # Windows 8, Windows server 2012
        "Core": "BN3D2-R7TKB-3YPBD-8DRP2-27GG4",
        "CoreARM": "DXHJF-N9KQX-MFPVR-GHGQK-Y7RKV",
        "CoreCountrySpecific": "4K36P-JN4VD-GDC6V-KDT89-DYFKP",
        "CoreN": "8N2M2-HWPGY-7PGT9-HGDD8-GVGGY",
        "CoreSingleLanguage": "2WN2H-YGCQR-KFX6K-CD6TF-84YXQ",
        "Enterprise": "32JNW-9KQ84-P47T8-D8GGY-CWCK7",
        "EnterpriseN": "JMNMF-RHW7P-DMY6X-RF3DR-X2BQT",
        "Professional": "NG4HW-VH26C-733KW-K6F98-J8CK4",
        "ProfessionalN": "XCVCF-2NXM9-723PB-MHCB7-2RYQQ",
        "ProfessionalWMC": "GNBB8-YVD74-QJHX6-27H4K-8QHDG",
        "ServerDatacenter": "48HP8-DN98B-MYWDG-T2DCC-8W83P",
        "ServerDatacenterCore": "48HP8-DN98B-MYWDG-T2DCC-8W83P",
        "ServerMultiPointStandard": "HM7DN-YVMH3-46JC3-XYTG7-CYQJJ",
        "ServerMultiPointPremium": "XNH6W-2V9GX-RGJ4K-Y8X6F-QGJ2G",
        "ServerStandard": "XC9B7-NBPP2-83J2H-RHMBY-92BT4",
        "ServerStandardCore": "XC9B7-NBPP2-83J2H-RHMBY-92BT4",
    },

    (6, 3, constant.VOL_ACT_KMS): {
        # Windows 8.1, Windows server 2012 R2
        "CoreARM": "XYTND-K6QKT-K2MRH-66RTM-43JKP",
        "ServerStandard": "D2N9P-3P6X9-2R39C-7RTCD-MDVJX",
        "ServerCloudStorageCore": "3NPTF-33KPT-GGBPR-YX76B-39KDD",
        "ServerCloudStorage": "3NPTF-33KPT-GGBPR-YX76B-39KDD",
        "EmbeddedIndustryA": "VHXM3-NR6FT-RY6RT-CK882-KW2CJ",
        "CoreN": "7B9N3-D94CG-YTVHR-QBPX3-RJP64",
        "CoreSingleLanguage": "BB6NG-PQ82V-VRDPW-8XVD2-V8P66",
        "ServerDatacenterCore": "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9",
        "Professional": "GCRJD-8NW9H-F2CDX-CCM8D-9D6T9",
        "ServerSolutionCore": "KNC87-3J2TX-XB4WP-VCPJV-M4FWM",
        "ServerSolution": "KNC87-3J2TX-XB4WP-VCPJV-M4FWM",
        "EmbeddedIndustryE": "FNFKF-PWTVT-9RC8H-32HB2-JB34X",
        "ProfessionalN": "HMCNV-VVBFX-7HMBH-CTY9B-B4FXY",
        "EmbeddedIndustry": "NMMPB-38DD4-R2823-62W8D-VXKJB",
        "CoreCountrySpecific": "NCTT7-2RGK8-WMHRF-RY7YQ-JTXG3",
        "ProfessionalWMC": "789NJ-TQK6T-6XTH8-J39CJ-J8D3P",
        "ServerDatacenter": "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9",
        "ServerStandardCore": "D2N9P-3P6X9-2R39C-7RTCD-MDVJX",
        "Enterprise": "MHF9N-XY6XB-WVXMC-BTDCT-MKKG7",
        "Core": "M9Q9P-WNJJT-6PXPY-DWX8H-6XWKK",
        "EnterpriseN": "TT4HM-HN7YT-62K67-RGRQJ-JFFXW",
    },

    (6, 3, constant.VOL_ACT_AVMA): {
        # Windows server 2012 R2
        "ServerSolutionCore": "K2XGM-NMBT3-2R6Q8-WF2FK-P36R2",
        "ServerDatacenterCore": "Y4TGP-NPTV9-HTC2H-7MGQ3-DV4TW",
        "ServerStandardCore": "DBGBW-NPF86-BJVTX-K3WKJ-MTB6V",
        "ServerSolution": "K2XGM-NMBT3-2R6Q8-WF2FK-P36R2",
        "ServerDatacenter": "Y4TGP-NPTV9-HTC2H-7MGQ3-DV4TW",
        "ServerStandard": "DBGBW-NPF86-BJVTX-K3WKJ-MTB6V",
    },

    (10, 0, constant.VOL_ACT_KMS): {
        # Windows 10, Windows Server 2016
        "Professional": "W269N-WFGWX-YVC9B-4J6C9-T83GX",
        "ProfessionalN": "MH37W-N47XK-V7XM9-C7227-GCQG9",
        "Enterprise": "NPPR9-FWDCX-D2C8J-H872K-2YT43",
        "EnterpriseN": "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4",
        "ServerDatacenterCore": "CB7KF-BWN84-R7R2Y-793K2-8XDDG",
        "ServerDatacenter": "CB7KF-BWN84-R7R2Y-793K2-8XDDG",
        "ServerStandardCore": "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY",
        "ServerStandard": "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY",
        "ServerSolutionCore": "JCKRF-N37P4-C2D82-9YXRT-4M63B",
        "ServerSolution": "JCKRF-N37P4-C2D82-9YXRT-4M63B",
        "ServerCloudStorage": "QN4C6-GBJD2-FB422-GHWJK-GJG2R",
        "ServerCloudStorageCore": "QN4C6-GBJD2-FB422-GHWJK-GJG2R",
        "ServerAzureCor": "VP34G-4NPPG-79JTQ-864T4-R3MQX",
        "ServerAzureCorCore": "VP34G-4NPPG-79JTQ-864T4-R3MQX",
    },

    (10, 0, constant.VOL_ACT_AVMA): {
        # Windows server 2016
        "ServerSolutionCore": "B4YNW-62DX9-W8V6M-82649-MHBKQ",
        "ServerDatacenterCore": "TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J",
        "ServerStandardCore": "C3RCX-M6NRP-6CXC9-TW2F2-4RHYD",
        "ServerSolution": "B4YNW-62DX9-W8V6M-82649-MHBKQ",
        "ServerDatacenter": "TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J",
        "ServerStandard": "C3RCX-M6NRP-6CXC9-TW2F2-4RHYD",
    },
}
