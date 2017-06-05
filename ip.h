struct ip_header {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                  
        u_short ip_off;                 
#define IP_RF 0x8000                    
#define IP_DF 0x4000                    
#define IP_MF 0x2000                    
#define IP_OFFMASK 0x1fff               
        u_char  ip_ttl;                 
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst;  
};
