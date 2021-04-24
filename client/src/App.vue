<template>
  <v-app>
    <div :class="{'nav-open': $sidebar.showSidebar}">
      <notifications></notifications>
      <router-view></router-view>
    </div>
  </v-app>
</template>

<script>
export default {};
</script>