import DashboardLayout from "@/layout/dashboard/DashboardLayout.vue";
// GeneralViews
import NotFound from "@/pages/NotFoundPage.vue";

// Main pages
import Domains_Subdomains from "@/pages/Domains_Subdomains.vue";
import IP_Addresses from "@/pages/IP_Addresses.vue";
import Emails from "@/pages/Email_Addresses.vue";
import Cloud_Buckets from "@/pages/Cloud_Buckets.vue";
import Notifications from "@/pages/Notifications.vue";
import Homepage from '@/pages/Homepage.vue';
const routes = [
  {
    path: "/",
    component: DashboardLayout,
    redirect: "/homepage",
    children: [
       {
        path: "homepage",
        name: "Home",
        component: Homepage
      },
      {
        path: "domains_subdomains",
        name: "Domains",
        component: Domains_Subdomains
      },
      {
        path: "ip_addresses",
        name: "IP Addresses",
        component: IP_Addresses
      },
      {
        path: "email_addresses",
        name: "Email Addresses",
        component: Emails
      },
      {
        path: "cloud_buckets",
        name: "Cloud Buckets",
        component: Cloud_Buckets
      },
      {
        path: "notifications",
        name: "Notification Centre",
        component: Notifications
      },
    ]
  },
  { path: "*", component: NotFound }
];

/**
 * Asynchronously load view (Webpack Lazy loading compatible)
 * The specified component must be inside the Views folder
 * @param  {string} name  the filename (basename) of the view to load.
function view(name) {
   var res= require('../components/Dashboard/Views/' + name + '.vue');
   return res;
};**/

export default routes;
