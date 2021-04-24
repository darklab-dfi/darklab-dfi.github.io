<template>
  <div class="wrapper">
    <side-bar>
      <template slot="links">
        <sidebar-link to="/domains_subdomains" name="Domains" icon="ti-direction-alt"/>
        <sidebar-link to="/ip_addresses" name="IP Addresses" icon="ti-vector"/>
        <sidebar-link to="/email_addresses" name="Email Addresses" icon="ti-email"/>
         <sidebar-link to="/cloud_buckets" name="Cloud Buckets" icon="ti-cloud-up"/>
      </template>
      <mobile-menu>
        <drop-down class="nav-item"
                   title="Notifications"
                   title-classes="nav-link"
                   icon="ti-bell">
          <a class="dropdown-item">Notification 1</a>
          <a class="dropdown-item">Notification 2</a>
          <a class="dropdown-item">Notification 3</a>
          <a class="dropdown-item">Notification 4</a>
          <a class="dropdown-item">Another notification</a>
        </drop-down>
        <li class="nav-item">
            <a href="#/profile" class="nav-link">
              <i class="ti-user"></i>
              <p>Profile</p>
            </a>
        </li>
        <li class="nav-item">
          <a class="nav-link">
            <i class="ti-settings"></i>
            <p>Settings</p>
          </a>
        </li>
        <li class="divider"></li>
      </mobile-menu>
    </side-bar>
    <div class="main-panel">
      <top-navbar></top-navbar>

      <dashboard-content @click.native="toggleSidebar">

      </dashboard-content>

      <content-footer></content-footer>
    </div>
  </div>
</template>
<style lang="scss">
</style>
<script>
import TopNavbar from "./TopNavbar.vue";
import ContentFooter from "./ContentFooter.vue";
import DashboardContent from "./Content.vue";
import MobileMenu from "./MobileMenu";
export default {
  components: {
    TopNavbar,
    ContentFooter,
    DashboardContent,
    MobileMenu
  },
  methods: {
    toggleSidebar() {
      if (this.$sidebar.showSidebar) {
        this.$sidebar.displaySidebar(false);
      }
    }
  }
};
</script>
